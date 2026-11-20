#include "reassembly.h"

typedef struct {
    unsigned family, protocol, id, more;
    size_t header, payload, length, offset, next_header_field;
    uint8_t source[16], destination[16];
} FRAGMENT_INFO;
static unsigned assembly_read16(const uint8_t *p) {return ((unsigned)p[0]<<8)|p[1];}
static void assembly_write16(uint8_t *p,unsigned v) {p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static void assembly_copy(uint8_t *out,const uint8_t *in,size_t size) {for(size_t n=0;n<size;n++)out[n]=in[n];}
static int assembly_equal(const uint8_t *a,const uint8_t *b,size_t size) {for(size_t n=0;n<size;n++)if(a[n]!=b[n])return 0;return 1;}

static int fragment_info(const uint8_t *raw,size_t size,FRAGMENT_INFO *info)
{
    if(!raw || !size)return -1;
    info->family=raw[0]>>4;
    size_t address_offset,address_size;
    if(info->family==4) {
        if(size<20 || (raw[0]&15)<5 || assembly_read16(raw+2)!=size)return -1;
        info->header=(raw[0]&15)*4;
        if(info->header>size)return -1;
        unsigned bits=assembly_read16(raw+6);
        if(!(bits&0x3fff))return 0;
        if(bits&0xc000)return -1;
        info->offset=(bits&8191)*8;
        info->more=(bits&0x2000)!=0;
        info->id=assembly_read16(raw+4);
        info->protocol=raw[9];
        info->payload=info->header;
        address_offset=12;address_size=4;
    } else if(info->family==6) {
        if(size<40 || 40+assembly_read16(raw+4)!=size)return -1;
        unsigned next=raw[6];size_t cursor=40;
        info->next_header_field=6;
        for(unsigned depth=0;next==0 || next==60;depth++) {
            if(depth>=8 || cursor+2>size)return -1;
            size_t width=((size_t)raw[cursor+1]+1)*8;
            if(width>size-cursor)return -1;
            info->next_header_field=cursor;next=raw[cursor];cursor+=width;
        }
        if(next!=44)return 0;
        if(cursor+8>size)return -1;
        unsigned bits=assembly_read16(raw+cursor+2);
        if(raw[cursor+1] || (bits&6))return -1;
        info->more=bits&1;info->offset=bits&65528;
        info->id=((unsigned)raw[cursor+4]<<24)|((unsigned)raw[cursor+5]<<16)|((unsigned)raw[cursor+6]<<8)|raw[cursor+7];
        info->protocol=raw[cursor];info->header=cursor;info->payload=cursor+8;
        address_offset=8;address_size=16;
    } else return -1;
    if(info->header>AIVPN_ASSEMBLY_HEADER || info->payload>=size)return -1;
    info->length=size-info->payload;
    if(info->offset>AIVPN_ASSEMBLY_BYTES-info->header || info->length>AIVPN_ASSEMBLY_BYTES-info->header-info->offset)return -1;
    if(info->more && (info->length%8))return -1;
    assembly_copy(info->source,raw+address_offset,address_size);
    assembly_copy(info->destination,raw+address_offset+address_size,address_size);
    return 1;
}

int aivpn_fragment_kind(const uint8_t *raw,size_t size)
{
    FRAGMENT_INFO info={0};return fragment_info(raw,size,&info);
}
size_t aivpn_reassembly_size(void) {return sizeof(AIVPN_REASSEMBLER);}

static AIVPN_ASSEMBLY *select_assembly(AIVPN_REASSEMBLER *state,const FRAGMENT_INFO *info,uint64_t context,uint64_t now)
{
    AIVPN_ASSEMBLY *free_slot=NULL;
    for(unsigned index=0;index<AIVPN_ASSEMBLY_LIMIT;index++) {
        AIVPN_ASSEMBLY *slot=&state->slots[index];
        if(slot->used && (now<slot->created || now-slot->created>=5000))slot->used=0;
        if(!slot->used) {if(!free_slot)free_slot=slot;continue;}
        if(slot->context==context && slot->family==info->family && slot->protocol==info->protocol && slot->id==info->id &&
            assembly_equal(slot->source,info->source,16) && assembly_equal(slot->destination,info->destination,16))return slot;
    }
    if(!free_slot)return NULL;
    AIVPN_ASSEMBLY *slot=free_slot;
    slot->used=1;slot->poisoned=0;slot->family=info->family;slot->protocol=info->protocol;slot->id=info->id;
    slot->created=now;slot->context=context;slot->total=slot->received=slot->header_size=0;slot->have_last=slot->have_first=0;
    for(size_t index=0;index<sizeof(slot->covered);index++)slot->covered[index]=0;
    assembly_copy(slot->source,info->source,16);assembly_copy(slot->destination,info->destination,16);
    return slot;
}

static int accept_fragment(AIVPN_ASSEMBLY *slot,const FRAGMENT_INFO *info,const uint8_t *raw)
{
    if(slot->poisoned)return -1;
    size_t end=info->offset+info->length;
    if((slot->have_last && end>slot->total) || (!info->more && slot->have_last && end!=slot->total))return -1;
    size_t first=info->offset/8,last=(end+7)/8;
    unsigned occupied=0;
    for(size_t index=first;index<last;index++)if(slot->covered[index/8]&(1u<<(index%8)))occupied++;
    if(occupied) {
        if(occupied!=last-first || !assembly_equal(slot->data+info->offset,raw+info->payload,info->length))return -1;
        if(!info->more && (!slot->have_last || slot->total!=end))return -1;
        return 0;
    }
    if(!info->more) {
        for(size_t index=last;index<sizeof(slot->covered)*8;index++)if(slot->covered[index/8]&(1u<<(index%8)))return -1;
        slot->total=end;slot->have_last=1;
    }
    if(!info->offset) {
        slot->header_size=info->header;slot->next_header_field=info->next_header_field;
        assembly_copy(slot->header,raw,info->header);slot->have_first=1;
    }
    assembly_copy(slot->data+info->offset,raw+info->payload,info->length);
    for(size_t index=first;index<last;index++)slot->covered[index/8]|=(uint8_t)(1u<<(index%8));
    slot->received+=info->length;
    return 0;
}

static void write_reassembled(AIVPN_ASSEMBLY *slot,uint8_t *out,size_t total)
{
    assembly_copy(out,slot->header,slot->header_size);
    assembly_copy(out+slot->header_size,slot->data,slot->total);
    if(slot->family==4) {
        assembly_write16(out+2,(unsigned)total);assembly_write16(out+6,0);assembly_write16(out+10,0);
        uint32_t sum=0;
        for(size_t index=0;index<slot->header_size;index+=2)sum+=assembly_read16(out+index);
        while(sum>>16)sum=(sum&65535)+(sum>>16);
        assembly_write16(out+10,(~sum)&65535);
    } else {
        out[slot->next_header_field]=(uint8_t)slot->protocol;
        assembly_write16(out+4,(unsigned)(total-40));
    }
}

int aivpn_reassemble_scoped(AIVPN_REASSEMBLER *state,uint64_t context,const uint8_t *raw,size_t size,uint64_t now_ms,
    uint8_t *out,size_t capacity,size_t *length)
{
    if(!length)return -1;
    *length=0;
    if(!state || !out)return -1;
    FRAGMENT_INFO info={0};
    int kind=fragment_info(raw,size,&info);
    if(kind!=1)return kind;
    AIVPN_ASSEMBLY *slot=select_assembly(state,&info,context,now_ms);
    if(!slot)return -1;
    if(accept_fragment(slot,&info,raw)<0) {slot->poisoned=1;return -1;}
    if(!slot->have_last || !slot->have_first || slot->received!=slot->total)return 1;
    size_t total=slot->header_size+slot->total;
    if(total>capacity || total>AIVPN_ASSEMBLY_BYTES) {slot->poisoned=1;return -1;}
    write_reassembled(slot,out,total);*length=total;slot->used=0;
    return 2;
}

int aivpn_reassemble(AIVPN_REASSEMBLER *state,const uint8_t *raw,size_t size,uint64_t now_ms,
    uint8_t *out,size_t capacity,size_t *length)
{
    return aivpn_reassemble_scoped(state,0,raw,size,now_ms,out,capacity,length);
}
