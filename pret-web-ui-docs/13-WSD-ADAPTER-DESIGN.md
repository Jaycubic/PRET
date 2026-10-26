# Phase 3 Extension — WSD (Web Services on Devices) Adapter Design

## 1. Problem and Objective

In enterprise and Windows-heavy environments, printers frequently communicate and expose services via **Web Services on Devices (WSD)** / **WS-Discovery** (OASIS standard, Devices Profile for Web Services / DPWS). 
While mDNS (Bonjour) catches many consumer/Apple-oriented devices, enterprise printers and Windows print servers primarily announce themselves via WS-Discovery on UDP port 3702 and host WSD endpoints on TCP port 5357 (or 80/3910/3911).

This adapter provides:
1. **Network Discovery**: Multicast UDP probe on `239.255.255.250:3702` targeting printer types (`print:PrintDeviceType`, `wsdp:Device`), returning discovered endpoint references and addresses.
2. **Device Identification / Metadata Probe**: Read-only unicast SOAP probe / WS-Transfer Get to retrieve hardware metadata (Manufacturer, ModelName, SerialNumber, FirmwareVersion, FriendlyName, UUID) from a target printer.

## 2. Protocol Details

### Discovery (WS-Discovery Probe)
- Transport: Multicast UDP `239.255.255.250:3702`
- Probe message: SOAP 1.2 envelope with `http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe` action.
- Response: `ProbeMatches` containing:
  - `wsa:EndpointReference` (UUID URN)
  - `wsd:Types`
  - `wsd:XAddrs` (HTTP URLs for device services, typically `http://<ip>:5357/...`)
  - `wsd:MetadataVersion`

### Metadata Retrieval (WS-Transfer Get / HTTP Probe)
- Transport: HTTP POST over port 5357 (or HTTP/HTTPS on device port)
- Request: WS-Transfer `http://schemas.xmlsoap.org/ws/2004/09/transfer/Get`
- Response: XML containing `<wsdp:ThisModel>`, `<wsdp:ThisDevice>`, with fields:
  - `FriendlyName`
  - `Manufacturer`
  - `ModelName`
  - `ModelNumber`
  - `SerialNumber`
  - `FirmwareVersion`

## 3. Scope & Security Enforcement

Per `05-SECURITY-ARCHITECTURE.md`:
1. Every discovered address from multicast responses is **strictly re-validated** against `authorized_networks` before being admitted to the database. Out-of-scope devices are rejected and logged.
2. When querying metadata over HTTP, redirect targets are checked against authorized scope (`validate_cb`), preventing SSRF.
3. XML parsing uses `defusedxml` / safe ElementTree parsing with entity expansion and external DTDs disabled to prevent XXE (XML External Entity) attacks.
4. All operations are strictly **read-only** (`read_only: true`).

## 4. Adapter Interface Implementation

- `id`: `"wsd"`
- `display_name`: `"WSD (Web Services on Devices)"`
- Operations:
  - `wsd_identify`: Probes target for WSD service and extracts model/vendor metadata.
  - `wsd_printer_summary`: Detailed query of printer services and capabilities exposed via DPWS.
- Discovery endpoint: `POST /api/discovery/wsd`
