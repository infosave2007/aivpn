#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
{
  printf '%s\n' 'import Foundation'
  sed -n '/^func lastLogTransitionIsConnected(/,/^}/p' aivpn-helper/main.swift
  printf '%s\n' \
    'guard !lastLogTransitionIsConnected("Connected to server at 192.0.2.1:443") else { print("FAIL: local setup claimed Connected"); exit(1) }' \
    'precondition(lastLogTransitionIsConnected("AIVPN-STATUS connected 10.0.0.2"))' \
    'precondition(!lastLogTransitionIsConnected("AIVPN-STATUS connected 10.0.0.2\nAIVPN-STATUS reconnecting\nConnected to server at 192.0.2.1:443"))' \
    'precondition(!lastLogTransitionIsConnected("AIVPN-STATUS connected 10.0.0.2\nAIVPN-STATUS rejected expired"))' \
    'print("PASS: only server-confirmed status establishes Connected")'
} | swift -
