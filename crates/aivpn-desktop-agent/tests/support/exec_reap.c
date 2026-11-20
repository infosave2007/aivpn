/* Только no-NIC fixture вызывает штатные guarded reaper programs. */
#include <assert.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../native/linux/routing.h"
static unsigned controls;
static unsigned long long control_cookies[16];

static int open_pin(const char *root,const char *kind,const char *name) {
    char path[512];assert(snprintf(path,sizeof(path),"%s/%s/%s",root,kind,name)>0);
    int fd=bpf_obj_get(path);assert(fd>=0);return fd;
}
static unsigned collect(int fd,void *keys,unsigned size) {
    unsigned count=0;
    while(count<1024 && !bpf_map_get_next_key(fd,count?(char *)keys+(count-1)*size:NULL,(char *)keys+count*size))count++;
    assert(count<1024);return count;
}
static void invoke(int program) {
    char packet[64]={0};struct bpf_test_run_opts options={.sz=sizeof(options),.data_in=packet,.data_size_in=sizeof(packet),.repeat=1};
    assert(bpf_prog_test_run_opts(program,&options)==0);
}
static unsigned routes(const char *root,const char *name,unsigned system) {
    int map=open_pin(root,"maps",name),request=open_pin(root,"maps","cache_reap_requests"),program=open_pin(root,"programs","reap_routing_cache");
    struct flow_key keys[1024];unsigned before=collect(map,keys,sizeof(keys[0]));
    for(unsigned i=0;i<before;i++) {
        struct route_cache_value value; if(bpf_map_lookup_elem(map,&keys[i],&value))continue;
        struct cache_reap_request row={.key=keys[i],.cookie=value.cookie,.epoch=value.epoch,.system=system};unsigned zero=0;
        assert(bpf_map_update_elem(request,&zero,&row,0)==0);invoke(program);
    }
    unsigned after=collect(map,keys,sizeof(keys[0]));
    unsigned remaining=0;
    for(unsigned i=0;i<after;i++) {
        if(system && keys[i].family==6 && keys[i].protocol==58 && !keys[i].port) {
            assert(controls<16);control_cookies[controls++]=keys[i].cookie;
        } else remaining++;
    }
    close(map);close(request);close(program);
    printf("\"%s\":{\"before\":%u,\"after\":%u,\"retained_keys\":[",name,before,after);
    for(unsigned i=0;i<after;i++) {
        printf("%s{\"cookie\":%llu,\"family\":%u,\"protocol\":%u,\"port\":%u,\"destination\":\"",i?",":"",(unsigned long long)keys[i].cookie,keys[i].family,keys[i].protocol,keys[i].port);
        for(unsigned n=0;n<16;n++)printf("%02x",keys[i].destination[n]);
        printf("\"}");
    }
    printf("]}");return remaining;
}
static unsigned tuples(const char *root) {
    int map=open_pin(root,"maps","tcp_routes"),request=open_pin(root,"maps","tcp_reap_requests"),program=open_pin(root,"programs","reap_tcp_routes");
    struct tcp_tuple keys[1024];unsigned before=collect(map,keys,sizeof(keys[0]));
    for(unsigned i=0;i<before;i++) {
        struct tcp_tuple_route value;if(bpf_map_lookup_elem(map,&keys[i],&value))continue;
        struct tcp_reap_request row={.tuple=keys[i],.cookie=value.cookie,.epoch=value.epoch,.expires=value.expires};unsigned zero=0;
        assert(bpf_map_update_elem(request,&zero,&row,0)==0);invoke(program);
    }
    unsigned after=collect(map,keys,sizeof(keys[0]));close(map);close(request);close(program);
    printf("\"tcp_routes\":{\"before\":%u,\"after\":%u}",before,after);return after;
}
int main(int argc,char **argv) {
    assert(argc==2 && geteuid()==0);FILE *f=fopen("/proc/cmdline","r");char line[4096];assert(f&&fgets(line,sizeof(line),f));fclose(f);
    assert(strstr(line,"aivpn.binding-snapshot=1"));unsigned left=0;
    printf("{");left+=routes(argv[1],"routing_overrides",0);printf(",");left+=routes(argv[1],"routing_system",1);printf(",");left+=tuples(argv[1]);
    for(unsigned i=0;i<2;i++) {const char *name=i?"routing_companions":"routing_subjects";int fd=open_pin(argv[1],"maps",name);unsigned long long keys[1024];unsigned n=collect(fd,keys,8);close(fd);printf(",\"%s\":%u",name,n);left+=n;}
    printf(",\"remaining_client_flows\":%u,\"kernel_icmp6_control_cookies\":[",left);
    for(unsigned i=0;i<controls;i++)printf("%s%llu",i?",":"",control_cookies[i]);
    printf("]}\n");return 0;
}
