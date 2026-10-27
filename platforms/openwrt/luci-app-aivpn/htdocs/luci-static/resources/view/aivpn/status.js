'use strict';
'require view';
'require rpc';
'require ui';
'require fs';

var callInitStatus = rpc.declare({
    object: 'service',
    method: 'list',
    params: ['name'],
    expect: { aivpn: {} }
});

return view.extend({
    load: function() {
        return callInitStatus('aivpn');
    },

    handleAction: function(action) {
        return fs.exec('/etc/init.d/aivpn', [action]).then(function(result) {
            if (result.code !== 0)
                throw new Error(_('Service command failed'));
            window.location.reload();
        }).catch(function(error) {
            ui.addNotification(null, E('p', {}, error.message));
        });
    },

    render: function(status) {
        var instances = status && status.instances || {};
        var running = Object.keys(instances).some(function(name) {
            return instances[name].running === true;
        });
        var readonly = !L.hasViewPermission();

        return E('div', { 'class': 'cbi-map' }, [
            E('h2', {}, _('AIVPN Status')),
            E('div', { 'class': 'cbi-section' }, [
                E('div', { 'class': 'table', 'style': 'width:100%' }, [
                    E('div', { 'class': 'tr' }, [
                        E('div', { 'class': 'td', 'style': 'width:30%' }, _('Service')),
                        E('div', { 'class': 'td' }, [
                            E('span', {
                                'class': running
                                    ? 'label-status label ok'
                                    : 'label-status label warning'
                            }, running ? _('Running') : _('Stopped'))
                        ])
                    ]),
                    E('div', { 'class': 'tr' }, [
                        E('div', { 'class': 'td' }, _('Tunnel Interface')),
                        E('div', { 'class': 'td' }, running ? 'aivpn0' : '—')
                    ])
                ]),
                E('div', {
                    'class': 'cbi-section-actions',
                    'style': 'margin-top:12px'
                }, [
                    E('button', {
                        'class': 'btn cbi-button cbi-button-action',
                        'disabled': running || readonly ? true : null,
                        'click': ui.createHandlerFn(this, 'handleAction', 'start')
                    }, _('Start')),
                    ' ',
                    E('button', {
                        'class': 'btn cbi-button cbi-button-negative',
                        'disabled': running && !readonly ? null : true,
                        'click': ui.createHandlerFn(this, 'handleAction', 'stop')
                    }, _('Stop'))
                ])
            ])
        ]);
    },

    handleSave: null,
    handleSaveApply: null,
    handleReset: null
});
