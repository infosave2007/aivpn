#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
{
  printf '%s\n' 'import Foundation' '#if os(Linux)' 'import Glibc' '#else' 'import Darwin' '#endif' 'func log(_ message: String) {}'
  sed -n '/^func readRegularFileNoFollow(/,/^}/p' aivpn-helper/main.swift
  printf '%s\n' \
    'let path = FileManager.default.temporaryDirectory.appendingPathComponent("aivpn-fifo-" + UUID().uuidString).path' \
    'guard mkfifo(path, 0o600) == 0 else { fatalError("mkfifo") }' \
    'defer { try? FileManager.default.removeItem(atPath: path) }' \
    'let done = DispatchSemaphore(value: 0)' \
    'DispatchQueue.global().async { precondition(readRegularFileNoFollow(path) == nil); done.signal() }' \
    'let result = done.wait(timeout: .now() + .milliseconds(100))' \
    'let writer = open(path, O_WRONLY | O_NONBLOCK)' \
    'if writer >= 0 { close(writer) }' \
    'guard result == .success else { print("FAIL: FIFO open blocked before fstat"); exit(1) }' \
    'print("PASS: FIFO rejected without waiting for writer")'
} | swift -
