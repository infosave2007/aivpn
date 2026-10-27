import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const source = readFileSync(join(import.meta.dir,
  '../../../openwrt/luci-app-aivpn/htdocs/luci-static/resources/view/aivpn/status.js'), 'utf8')
function fixture(code = 0, readonly = false) {
  let reloads = 0
  const notices: unknown[] = []
  const executed: unknown[] = []
  const rpc = { declare: (spec: any) => async (name: string) => {
    if (spec.object !== 'service' || spec.method !== 'list') throw Error('Unknown RPC method')
    expect(name).toBe('aivpn')
    const response = { aivpn: { instances: { idle: { running: false }, main: { running: true } } } }
    return spec.expect.aivpn ? response.aivpn : response
  } }
  const ui = { createHandlerFn: () => {}, addNotification: (...args: unknown[]) => notices.push(args) }
  const fs = { exec: async (...args: unknown[]) => { executed.push(args); return { code, stderr: 'failure' } } }
  const E = (tag: string, attrs: any, children: any) => ({ tag, attrs, children })
  const view = new Function('view', 'rpc', 'fs', 'ui', 'E', '_', 'L', 'window', source)(
    { extend: (v: unknown) => v }, rpc, fs, ui, E, (v: string) => v,
    { hasViewPermission: () => !readonly }, { location: { reload: () => reloads++ } })
  return { view, notices, executed, reloads: () => reloads }
}

test('OpenWrt показывает реально запущенный экземпляр procd', async () => {
  const { view } = fixture()
  const rendered = JSON.stringify(view.render(await view.load()))
  expect(rendered).toContain('Running')
  expect(JSON.stringify(view.render({}))).toContain('Stopped')
})
test('OpenWrt не скрывает ошибку команды перезагрузкой страницы', async () => {
  const failed = fixture(1)
  await failed.view.handleAction('start')
  expect(failed.executed).toEqual([['/etc/init.d/aivpn', ['start']]])
  expect(failed.reloads()).toBe(0)
  expect(failed.notices.length).toBe(1)
  const success = fixture()
  await success.view.handleAction('stop')
  expect(success.reloads()).toBe(1)
})
