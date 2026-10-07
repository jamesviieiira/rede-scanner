// =============================================================
//  REDE SCANNER - Single Page App (Material 3)
//  Alvo: Android 7.1+ (LG K9). Funciona em versões mais novas,
//  mas a tabela ARP (/proc/net/arp) só é legível no Android <= 9.
// =============================================================
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:http/http.dart' as http;
import 'package:multicast_dns/multicast_dns.dart';
import 'package:network_info_plus/network_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:share_plus/share_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:wifi_scan/wifi_scan.dart';

void main() => runApp(const RedeScannerApp());

// ------------------------------------------------------------
//  TEMA (claro/escuro)
// ------------------------------------------------------------
final ValueNotifier<ThemeMode> themeMode = ValueNotifier(ThemeMode.system);

ThemeData _buildTheme(Brightness b) => ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.fromSeed(
        seedColor: const Color(0xFF3F51B5),
        brightness: b,
      ),
    );

class RedeScannerApp extends StatelessWidget {
  const RedeScannerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: themeMode,
      builder: (_, mode, __) => MaterialApp(
        title: 'Rede Scanner',
        debugShowCheckedModeBanner: false,
        themeMode: mode,
        theme: _buildTheme(Brightness.light),
        darkTheme: _buildTheme(Brightness.dark),
        home: const HomePage(),
      ),
    );
  }
}

// ------------------------------------------------------------
//  CONSTANTES DE DETECÇÃO
// ------------------------------------------------------------

/// Portas sondadas em cada IP (também servem para detectar host vivo).
const List<int> kScanPorts = [
  80, 443, 554, 8554, 8000, 8080, 8443, 8899, 37777, 37778,
  34567, 1935, 9000, 23, 22, 53, 139, 445, 5555, 49152,
];

/// Palavras fortes: se aparecerem em título/servidor/realm/SSDP, é câmera/DVR.
const List<String> kStrongKeywords = [
  'ipcam', 'ip camera', 'ipc-', 'dvr', 'nvr', 'hikvision', 'dahua',
  'camera', 'webcam', 'onvif', 'ezviz', 'reolink', 'tapo', 'foscam',
  'amcrest', 'uniview', 'imou', 'xmeye', 'netsurveillance', 'hi3510',
  'dnvrs', 'app-webs', 'cctv', 'surveillance', 'espcam', 'esp32-cam',
  'v380', 'yi home', 'wyze', 'rtsp',
];

/// Servidores web embarcados típicos de câmeras baratas (indício fraco).
const List<String> kEmbeddedServers = [
  'goahead', 'uc-httpd', 'boa/', 'mini_httpd', 'thttpd', 'jaws/', 'gsoap',
];

const List<String> kCameraVendors = [
  'hikvision', 'dahua', 'ezviz', 'reolink', 'uniview', 'amcrest', 'foscam',
  'imou', 'axis communications', 'hanwha', 'vivotek', 'wyze', 'arlo',
  'lorex', 'swann', 'annke', 'xiongmai', 'hisilicon', 'tiandy', 'milesight',
];

const List<String> kIotVendors = ['espressif', 'tuya', 'ai-thinker'];

/// Mini tabela OUI offline (prefixos comuns). A API cobre o resto.
const Map<String, String> kLocalOui = {
  'C0:56:E3': 'Hangzhou Hikvision Digital Technology',
  '44:19:B6': 'Hangzhou Hikvision Digital Technology',
  'BC:AD:28': 'Hangzhou Hikvision Digital Technology',
  '28:57:BE': 'Hangzhou Hikvision Digital Technology',
  '4C:BD:8F': 'Hangzhou Hikvision Digital Technology',
  'A4:14:37': 'Hangzhou Hikvision Digital Technology',
  '54:C4:15': 'Hangzhou Hikvision Digital Technology',
  '18:68:CB': 'Hangzhou Hikvision Digital Technology',
  '3C:EF:8C': 'Zhejiang Dahua Technology',
  '4C:11:AE': 'Zhejiang Dahua Technology',
  '9C:14:63': 'Zhejiang Dahua Technology',
  'E0:50:8B': 'Zhejiang Dahua Technology',
  'A0:BD:1D': 'Zhejiang Dahua Technology',
  '90:02:A9': 'Zhejiang Dahua Technology',
  '24:0A:C4': 'Espressif Inc.',
  '30:AE:A4': 'Espressif Inc.',
  '24:6F:28': 'Espressif Inc.',
  'A4:CF:12': 'Espressif Inc.',
  '5C:CF:7F': 'Espressif Inc.',
  '84:0D:8E': 'Espressif Inc.',
  'EC:FA:BC': 'Espressif Inc.',
  'CC:50:E3': 'Espressif Inc.',
  'B4:E6:2D': 'Espressif Inc.',
  '3C:71:BF': 'Espressif Inc.',
};

/// Nomes de Wi-Fi típicos de câmeras: IPC-1234, HK-ab12, V380_xxxx...
final RegExp kSuspectSsid = RegExp(
  r'^(ipc|ipcam|hk|hik|dvr|nvr|cam|camera|hdwificam|minicam|v380|ycc365|a9|'
  r'ppcs|cloudedge|esp|esp32|espcam|tuya|smartlife|onvif|batcam|wificam|'
  r'spycam|xmeye|hdcam)(?:[-_ ][0-9a-z]{3,}|[0-9]{3,})$',
  caseSensitive: false,
);

final RegExp kBleSuspectName = RegExp(
  r'(cam|camera|mic|microphone|recorder|spy|tracker|bug|gps|dvr|esp32|esp-|jdy|bt05|listen)',
  caseSensitive: false,
);

// ------------------------------------------------------------
//  MODELOS
// ------------------------------------------------------------
enum Risk { baixo, medio, alto }

Color riskColor(Risk r) => switch (r) {
      Risk.alto => const Color(0xFFC62828),
      Risk.medio => const Color(0xFFEF6C00),
      Risk.baixo => const Color(0xFF2E7D32),
    };

String riskLabel(Risk r) => switch (r) {
      Risk.alto => 'ALTO',
      Risk.medio => 'MÉDIO',
      Risk.baixo => 'BAIXO',
    };

Risk riskFromScore(int s) => s >= 60 ? Risk.alto : (s >= 30 ? Risk.medio : Risk.baixo);

class Device {
  final String ip;
  String? mac;
  String? vendor;
  final Set<int> openPorts = {};
  String? webTitle, serverHeader, realm, rtspServer;
  String webText = '';
  bool rtspConfirmed = false;
  String? onvifInfo, ssdpInfo, mdnsInfo;
  int score = 0;
  final List<String> reasons = [];
  bool isNew = false;

  Device(this.ip);

  Risk get risk => riskFromScore(score);
  String get key => mac ?? ip;
}

class WifiSus {
  final String ssid, bssid;
  final int level;
  final int score;
  final List<String> reasons;
  WifiSus(this.ssid, this.bssid, this.level, this.score, this.reasons);
}

class BleDev {
  final String id, name;
  final int rssi;
  int score = 0;
  final List<String> reasons = [];
  BleDev(this.id, this.name, this.rssi);
}

class VendorResp {
  final String? name;
  final String? error;
  final bool fromApi;
  VendorResp({this.name, this.error, this.fromApi = false});
}

class VendorStyle {
  final IconData icon;
  final Color color;
  final String category;
  const VendorStyle(this.icon, this.color, this.category);
}

VendorStyle vendorStyle(String? name) {
  final n = (name ?? '').toLowerCase();
  bool has(List<String> l) => l.any(n.contains);
  if (n.isEmpty) return const VendorStyle(Icons.help_outline, Color(0xFF757575), 'Desconhecido');
  if (has(kCameraVendors)) return const VendorStyle(Icons.videocam, Color(0xFFC62828), 'Câmera / DVR');
  if (has(kIotVendors)) return const VendorStyle(Icons.memory, Color(0xFFEF6C00), 'IoT / microcontrolador');
  if (has(['apple'])) return const VendorStyle(Icons.phone_iphone, Color(0xFF546E7A), 'Apple');
  if (has(['samsung', 'xiaomi', 'huawei', 'motorola', 'lg elec', 'oneplus', 'oppo', 'vivo', 'realme'])) {
    return const VendorStyle(Icons.smartphone, Color(0xFF1565C0), 'Celular / tablet');
  }
  if (has(['tp-link', 'd-link', 'netgear', 'asus', 'mikrotik', 'ubiquiti', 'zte', 'cisco', 'tenda', 'intelbras'])) {
    return const VendorStyle(Icons.router, Color(0xFF6A1B9A), 'Roteador / rede');
  }
  if (has(['google', 'amazon', 'sonos', 'roku'])) {
    return const VendorStyle(Icons.speaker, Color(0xFF00838F), 'Casa inteligente');
  }
  if (has(['intel', 'realtek', 'dell', 'hewlett', 'lenovo', 'microsoft'])) {
    return const VendorStyle(Icons.computer, Color(0xFF3949AB), 'Computador');
  }
  return const VendorStyle(Icons.devices_other, Color(0xFF455A64), 'Outro');
}

// ------------------------------------------------------------
//  SKELETON (efeito shimmer simples, sem pacote externo)
// ------------------------------------------------------------
class Skeleton extends StatefulWidget {
  final double height;
  const Skeleton({super.key, this.height = 72});

  @override
  State<Skeleton> createState() => _SkeletonState();
}

class _SkeletonState extends State<Skeleton> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 900),
  )..repeat(reverse: true);

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final base = Theme.of(context).colorScheme.surfaceContainerHighest;
    return AnimatedBuilder(
      animation: _c,
      builder: (_, __) => Container(
        height: widget.height,
        decoration: BoxDecoration(
          color: base.withAlpha((90 + _c.value * 120).toInt()),
          borderRadius: BorderRadius.circular(20),
        ),
      ),
    );
  }
}

// Formata o MAC enquanto digita: AA:BB:CC:DD:EE:FF
class MacFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(TextEditingValue oldValue, TextEditingValue newValue) {
    var hex = newValue.text.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toUpperCase();
    if (hex.length > 12) hex = hex.substring(0, 12);
    final b = StringBuffer();
    for (var i = 0; i < hex.length; i++) {
      if (i > 0 && i % 2 == 0) b.write(':');
      b.write(hex[i]);
    }
    final s = b.toString();
    return TextEditingValue(text: s, selection: TextSelection.collapsed(offset: s.length));
  }
}

// ------------------------------------------------------------
//  TELA ÚNICA
// ------------------------------------------------------------
class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final NetworkInfo _info = NetworkInfo();
  Timer? _wifiTimer;
  bool _refreshingWifi = false;

  // --- Sinal Wi-Fi ---
  String? _ssid, _bssid, _myIp;
  int? _rssi;
  List<WiFiAccessPoint> _aps = [];
  bool _gpsOff = false;

  // --- Varredura de rede ---
  bool _scanning = false;
  bool _vendorBusy = false;
  bool _scannedOnce = false;
  double _progress = 0;
  String _phase = '';
  List<Device> _devices = [];
  bool _firstRun = false;
  int _gone = 0;

  // --- BLE ---
  bool _bleBusy = false;
  List<BleDev> _ble = [];
  String? _bleMsg;

  // --- Busca de MAC ---
  final TextEditingController _macCtl = TextEditingController();
  bool _macBusy = false;
  VendorResp? _macResp;
  String? _macShown;

  final Map<String, String> _ouiCache = {};

  @override
  void initState() {
    super.initState();
    _init();
  }

  @override
  void dispose() {
    _wifiTimer?.cancel();
    _macCtl.dispose();
    super.dispose();
  }

  Future<void> _init() async {
    await [Permission.locationWhenInUse].request();
    await _refreshWifi();
    _wifiTimer = Timer.periodic(const Duration(seconds: 6), (_) => _refreshWifi());
  }

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(msg), behavior: SnackBarBehavior.floating));
  }

  // ============================================================
  //  1) SINAL WI-FI (RSSI)
  // ============================================================
  Future<void> _refreshWifi() async {
    if (_refreshingWifi) return;
    _refreshingWifi = true;
    try {
      final svc = await Permission.locationWhenInUse.serviceStatus;
      var ssid = await _info.getWifiName();
      final bssid = await _info.getWifiBSSID();
      final ip = await _info.getWifiIP();
      ssid = ssid?.replaceAll('"', '');

      final scan = WiFiScan.instance;
      if (await scan.canStartScan(askPermissions: false) == CanStartScan.yes) {
        await scan.startScan();
        await Future.delayed(const Duration(seconds: 2));
      }
      var aps = _aps;
      if (await scan.canGetScannedResults(askPermissions: false) == CanGetScannedResults.yes) {
        aps = await scan.getScannedResults();
      }

      // Procura a rede atual pelo BSSID (ou pelo SSID como reserva).
      int? rssi;
      for (final ap in aps) {
        if (bssid != null && ap.bssid.toLowerCase() == bssid.toLowerCase()) {
          rssi = ap.level;
          break;
        }
      }
      if (rssi == null && ssid != null) {
        for (final ap in aps) {
          if (ap.ssid == ssid && (rssi == null || ap.level > rssi)) rssi = ap.level;
        }
      }

      if (!mounted) return;
      setState(() {
        _gpsOff = svc != ServiceStatus.enabled;
        _ssid = ssid;
        _bssid = bssid;
        _myIp = ip;
        _aps = aps;
        _rssi = rssi;
      });
    } catch (_) {
      // Ignora falhas pontuais de leitura.
    } finally {
      _refreshingWifi = false;
    }
  }

  // ============================================================
  //  2) VARREDURA DE REDE
  // ============================================================

  /// 1 = porta aberta, 0 = recusada (host vivo), -1 = sem resposta.
  Future<int> _probePort(String ip, int port) async {
    try {
      final s = await Socket.connect(ip, port, timeout: const Duration(milliseconds: 700));
      s.destroy();
      return 1;
    } on SocketException catch (e) {
      final c = e.osError?.errorCode;
      if (c == 111 || c == 61) return 0; // ECONNREFUSED -> host está vivo
      return -1;
    } catch (_) {
      return -1;
    }
  }

  Future<Device?> _probeHost(String ip) async {
    final res = await Future.wait(kScanPorts.map((p) => _probePort(ip, p)));
    var alive = false;
    final d = Device(ip);
    for (var i = 0; i < res.length; i++) {
      if (res[i] >= 0) alive = true;
      if (res[i] == 1) d.openPorts.add(kScanPorts[i]);
    }
    return alive ? d : null;
  }

  /// Lê a tabela ARP (funciona no Android 7.1; bloqueada no Android 10+).
  Future<Map<String, String>> _readArp() async {
    final out = <String, String>{};
    try {
      final lines = await File('/proc/net/arp').readAsLines();
      for (final l in lines.skip(1)) {
        final p = l.trim().split(RegExp(r'\s+'));
        if (p.length >= 4 && p[2] == '0x2' && p[3] != '00:00:00:00:00:00') {
          out[p[0]] = p[3].toUpperCase();
        }
      }
    } catch (_) {}
    return out;
  }

  int _ipLast(String ip) => int.tryParse(ip.split('.').last) ?? 0;

  void _sortDevices() {
    _devices.sort((a, b) {
      final c = b.score.compareTo(a.score);
      return c != 0 ? c : _ipLast(a.ip).compareTo(_ipLast(b.ip));
    });
  }

  Future<void> _startScan() async {
    if (_scanning) return;
    final ip = await _info.getWifiIP();
    if (ip == null || !RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(ip)) {
      _snack('Conecte-se a uma rede Wi-Fi primeiro.');
      return;
    }
    final base = ip.substring(0, ip.lastIndexOf('.'));
    setState(() {
      _scanning = true;
      _progress = 0;
      _devices = [];
      _myIp = ip;
      _phase = 'Varrendo $base.1–254…';
    });

    final found = <String, Device>{};
    final hosts = [for (var i = 1; i <= 254; i++) '$base.$i']..remove(ip);

    // ---- Fase 1: sondagem de portas (0% a 50%) ----
    const batch = 16;
    for (var i = 0; i < hosts.length; i += batch) {
      final slice = hosts.sublist(i, min(i + batch, hosts.length));
      final res = await Future.wait(slice.map(_probeHost));
      for (final d in res) {
        if (d != null) found[d.ip] = d;
      }
      if (!mounted) return;
      setState(() {
        _progress = min(1.0, (i + batch) / hosts.length) * 0.5;
        _devices = found.values.toList();
        _sortDevices();
      });
    }

    // ---- Fase 2: ARP (acha até quem bloqueia todas as portas) ----
    setState(() => _phase = 'Lendo tabela ARP…');
    final arp = await _readArp();
    for (final e in arp.entries) {
      if (!e.key.startsWith('$base.') || e.key == ip) continue;
      final d = found.putIfAbsent(e.key, () => Device(e.key));
      d.mac = e.value;
    }

    // ---- Fase 3: descoberta (ONVIF/SSDP/mDNS) em paralelo com análise ----
    setState(() => _phase = 'Analisando RTSP, páginas web e anúncios…');
    final discoveryFuture = Future.wait<Map<String, String>>([
      _discoverOnvif(),
      _discoverSsdp(),
      _discoverMdns(),
    ]);

    final list = found.values.toList();
    for (var i = 0; i < list.length; i += 6) {
      final slice = list.sublist(i, min(i + 6, list.length));
      await Future.wait(slice.map(_analyze));
      if (!mounted) return;
      setState(() => _progress = 0.5 + 0.3 * min(1.0, (i + 6) / max(1, list.length)));
    }

    final disc = await discoveryFuture;
    for (final e in disc[0].entries) {
      if (e.key.startsWith('$base.') && e.key != ip) {
        found.putIfAbsent(e.key, () => Device(e.key)).onvifInfo = e.value;
      }
    }
    for (final e in disc[1].entries) {
      if (e.key.startsWith('$base.') && e.key != ip) {
        found.putIfAbsent(e.key, () => Device(e.key)).ssdpInfo = e.value;
      }
    }
    for (final e in disc[2].entries) {
      if (e.key.startsWith('$base.') && e.key != ip) {
        found.putIfAbsent(e.key, () => Device(e.key)).mdnsInfo = e.value;
      }
    }

    // ---- Fase 4: pontuação + comparação com varredura anterior ----
    setState(() {
      _phase = 'Calculando risco…';
      _progress = 0.95;
    });
    final all = found.values.toList();
    for (final d in all) {
      if (d.mac != null) {
        d.vendor = kLocalOui[d.mac!.substring(0, 8)];
      }
      _evaluate(d);
    }

    final prefs = await SharedPreferences.getInstance();
    final prevRaw = prefs.getString('last_scan');
    final Map<String, dynamic> prev = prevRaw == null ? {} : (jsonDecode(prevRaw) as Map<String, dynamic>);
    final keys = all.map((d) => d.key).toSet();
    _firstRun = prev.isEmpty;
    for (final d in all) {
      d.isNew = !_firstRun && !prev.containsKey(d.key);
    }
    _gone = prev.keys.where((k) => !keys.contains(k)).length;
    await prefs.setString('last_scan', jsonEncode({for (final d in all) d.key: d.ip}));

    if (!mounted) return;
    setState(() {
      _devices = all;
      _sortDevices();
      _scanning = false;
      _scannedOnce = true;
      _progress = 1;
      _phase = '';
    });

    _lookupVendors();
  }

  // ---------- Análise individual ----------
  Future<void> _analyze(Device d) async {
    await Future.wait([_checkRtsp(d), _fetchWeb(d)]);
  }

  /// Envia OPTIONS RTSP. Se responder "RTSP/1.0", é câmera/DVR.
  Future<void> _checkRtsp(Device d) async {
    for (final port in [554, 8554]) {
      if (!d.openPorts.contains(port)) continue;
      try {
        final s = await Socket.connect(d.ip, port, timeout: const Duration(seconds: 3));
        s.write('OPTIONS rtsp://${d.ip}:$port/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: RedeScanner\r\n\r\n');
        await s.flush();
        final data = await s.first.timeout(const Duration(seconds: 3));
        final txt = utf8.decode(data, allowMalformed: true);
        s.destroy();
        if (txt.startsWith('RTSP/')) {
          d.rtspConfirmed = true;
          d.rtspServer = RegExp(r'^Server:\s*(.+)$', multiLine: true, caseSensitive: false)
              .firstMatch(txt)
              ?.group(1)
              ?.trim();
          return;
        }
      } catch (_) {}
    }
  }

  /// Lê título da página, cabeçalho Server e realm da autenticação.
  Future<void> _fetchWeb(Device d) async {
    for (final port in [80, 8080, 443, 8443, 8000, 9000]) {
      if (!d.openPorts.contains(port)) continue;
      final https = port == 443 || port == 8443;
      final client = HttpClient()
        ..connectionTimeout = const Duration(seconds: 3)
        ..badCertificateCallback = (_, __, ___) => true;
      try {
        final req = await client
            .getUrl(Uri.parse('${https ? 'https' : 'http'}://${d.ip}:$port/'))
            .timeout(const Duration(seconds: 4));
        req.headers.set('User-Agent', 'Mozilla/5.0');
        final resp = await req.close().timeout(const Duration(seconds: 4));
        d.serverHeader ??= resp.headers.value('server');
        final auth = resp.headers.value('www-authenticate');
        if (auth != null) {
          d.realm ??= RegExp(r'realm="?([^",]+)').firstMatch(auth)?.group(1);
        }
        final bytes = <int>[];
        await for (final chunk in resp.timeout(const Duration(seconds: 3))) {
          bytes.addAll(chunk);
          if (bytes.length > 8192) break;
        }
        final body = utf8.decode(bytes, allowMalformed: true);
        d.webTitle ??= RegExp(r'<title[^>]*>([^<]*)</title>', caseSensitive: false)
            .firstMatch(body)
            ?.group(1)
            ?.trim();
        d.webText = body.length > 3000 ? body.substring(0, 3000) : body;
        if (d.webTitle != null || d.serverHeader != null || d.realm != null) return;
      } catch (_) {
      } finally {
        client.close(force: true);
      }
    }
  }

  // ---------- Descobertas multicast ----------
  String _rndHex(int n) {
    final r = Random();
    return List.generate(n, (_) => r.nextInt(16).toRadixString(16)).join();
  }

  /// ONVIF / WS-Discovery (UDP 3702).
  Future<Map<String, String>> _discoverOnvif() async {
    final out = <String, String>{};
    RawDatagramSocket? sock;
    try {
      sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final uuid = '${_rndHex(8)}-${_rndHex(4)}-${_rndHex(4)}-${_rndHex(4)}-${_rndHex(12)}';
      final msg = '<?xml version="1.0" encoding="UTF-8"?>'
          '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
          'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
          'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
          'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
          '<e:Header><w:MessageID>uuid:$uuid</w:MessageID>'
          '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
          '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
          '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>';
      final s = sock;
      s.listen((ev) {
        if (ev == RawSocketEvent.read) {
          final dg = s.receive();
          if (dg == null) return;
          final t = utf8.decode(dg.data, allowMalformed: true);
          final name = RegExp(r'onvif://www\.onvif\.org/name/([^\s<]+)').firstMatch(t)?.group(1);
          final hw = RegExp(r'onvif://www\.onvif\.org/hardware/([^\s<]+)').firstMatch(t)?.group(1);
          out[dg.address.address] = [name, hw].whereType<String>().join(' / ');
        }
      });
      s.send(utf8.encode(msg), InternetAddress('239.255.255.250'), 3702);
      await Future.delayed(const Duration(seconds: 4));
    } catch (_) {
    } finally {
      sock?.close();
    }
    return out;
  }

  /// SSDP / UPnP (UDP 1900).
  Future<Map<String, String>> _discoverSsdp() async {
    final out = <String, String>{};
    RawDatagramSocket? sock;
    try {
      sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      const msg = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
          'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n';
      final s = sock;
      s.listen((ev) {
        if (ev == RawSocketEvent.read) {
          final dg = s.receive();
          if (dg == null) return;
          final t = utf8.decode(dg.data, allowMalformed: true);
          final server = RegExp(r'^SERVER:\s*(.+)$', multiLine: true, caseSensitive: false)
              .firstMatch(t)
              ?.group(1)
              ?.trim();
          final st = RegExp(r'^ST:\s*(.+)$', multiLine: true, caseSensitive: false)
              .firstMatch(t)
              ?.group(1)
              ?.trim();
          final line = [server, st].whereType<String>().join(' | ');
          final old = out[dg.address.address];
          if (old == null) {
            out[dg.address.address] = line;
          } else if (!old.contains(line) && old.length < 400) {
            out[dg.address.address] = '$old\n$line';
          }
        }
      });
      s.send(utf8.encode(msg), InternetAddress('239.255.255.250'), 1900);
      await Future.delayed(const Duration(seconds: 4));
    } catch (_) {
    } finally {
      sock?.close();
    }
    return out;
  }

  /// mDNS / Bonjour (UDP 5353).
  Future<Map<String, String>> _discoverMdns() async {
    final out = <String, String>{};
    final client = MDnsClient(
      rawDatagramSocketFactory: (dynamic host, int port,
              {bool reuseAddress = true, bool reusePort = true, int ttl = 1}) =>
          RawDatagramSocket.bind(host, port, reuseAddress: true, reusePort: false, ttl: ttl),
    );
    Stream<T> limit<T>(Stream<T> s, int secs) =>
        s.timeout(Duration(seconds: secs), onTimeout: (sink) => sink.close());
    try {
      await client.start();
      const services = [
        '_rtsp._tcp.local', '_onvif._tcp.local', '_camera._tcp.local',
        '_http._tcp.local', '_hap._tcp.local', '_googlecast._tcp.local',
      ];
      for (final svc in services) {
        await for (final PtrResourceRecord ptr
            in limit(client.lookup<PtrResourceRecord>(ResourceRecordQuery.serverPointer(svc)), 2)) {
          await for (final SrvResourceRecord srv in limit(
              client.lookup<SrvResourceRecord>(ResourceRecordQuery.service(ptr.domainName)), 1)) {
            await for (final IPAddressResourceRecord a in limit(
                client.lookup<IPAddressResourceRecord>(ResourceRecordQuery.addressIPv4(srv.target)), 1)) {
              final ip = a.address.address;
              final entry = '$svc (${ptr.domainName.split('.').first})';
              final old = out[ip];
              out[ip] = old == null ? entry : (old.length < 400 ? '$old\n$entry' : old);
            }
          }
        }
      }
    } catch (_) {
    } finally {
      try {
        client.stop();
      } catch (_) {}
    }
    return out;
  }

  // ---------- Pontuação de risco ----------
  void _evaluate(Device d) {
    d.score = 0;
    d.reasons.clear();
    void add(int p, String why) {
      d.score += p;
      d.reasons.add(why);
    }

    final p = d.openPorts;
    if (d.rtspConfirmed) {
      add(60, 'Responde ao protocolo de vídeo RTSP${d.rtspServer != null ? ' (${d.rtspServer})' : ''}');
    } else if (p.contains(554) || p.contains(8554)) {
      add(35, 'Porta RTSP aberta (554/8554)');
    }
    if (p.contains(37777) || p.contains(37778)) add(45, 'Porta 37777 aberta (padrão Dahua)');
    if (p.contains(8000)) add(25, 'Porta 8000 aberta (padrão Hikvision)');
    if (p.contains(34567)) add(30, 'Porta 34567 aberta (DVR/XMEye)');
    if (p.contains(8899)) add(20, 'Porta 8899 aberta (câmeras IP genéricas)');
    if (p.contains(1935)) add(15, 'Porta 1935 aberta (streaming RTMP)');
    if (p.contains(23)) add(10, 'Telnet aberto (comum em câmeras baratas)');

    final v = (d.vendor ?? '').toLowerCase();
    if (kCameraVendors.any(v.contains)) {
      add(40, 'Fabricante de câmeras: ${d.vendor}');
    } else if (kIotVendors.any(v.contains)) {
      add(30, 'Chip/placa IoT (ESP32/ESP8266/Tuya): ${d.vendor}');
    } else if (v.contains('intelbras')) {
      add(15, 'Fabricante que também produz câmeras: ${d.vendor}');
    }

    final web = '${d.webTitle ?? ''} ${d.serverHeader ?? ''} ${d.realm ?? ''} ${d.webText}'.toLowerCase();
    final kw = kStrongKeywords.where(web.contains).toList();
    if (kw.isNotEmpty) {
      add(40, 'Página web/servidor/login se identifica como câmera ("${kw.first}")');
    } else if (kEmbeddedServers.any(web.contains)) {
      add(15, 'Servidor web embarcado típico de câmera (${d.serverHeader ?? 'cabeçalho'})');
    }

    if (d.onvifInfo != null) {
      add(50, 'Anunciou-se via ONVIF${d.onvifInfo!.isNotEmpty ? ': ${d.onvifInfo}' : ''}');
    }
    final ssdp = (d.ssdpInfo ?? '').toLowerCase();
    if (kStrongKeywords.any(ssdp.contains)) add(35, 'Anúncio UPnP/SSDP indica câmera/DVR');
    final mdns = (d.mdnsInfo ?? '').toLowerCase();
    if (mdns.contains('_rtsp') || mdns.contains('_onvif') || mdns.contains('_camera')) {
      add(40, 'Anúncio mDNS de serviço de vídeo/câmera');
    }
    if (d.score > 100) d.score = 100;
  }

  // ============================================================
  //  3) CONSULTA DE FABRICANTE (OUI)
  // ============================================================
  String? _normalizeMac(String raw) {
    final hex = raw.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toUpperCase();
    if (hex.length < 6) return null;
    final b = StringBuffer();
    for (var i = 0; i < hex.length; i++) {
      if (i > 0 && i % 2 == 0) b.write(':');
      b.write(hex[i]);
    }
    return b.toString();
  }

  bool _isRandomMac(String mac) {
    final c = mac.substring(1, 2);
    return '26AE'.contains(c); // bit "localmente administrado"
  }

  Future<VendorResp> _lookupVendor(String mac) async {
    final oui = mac.substring(0, 8);
    final local = kLocalOui[oui];
    if (local != null) return VendorResp(name: local);
    if (_ouiCache.containsKey(oui)) return VendorResp(name: _ouiCache[oui]);
    try {
      final r = await http
          .get(Uri.parse('https://api.macvendors.com/${Uri.encodeComponent(mac)}'))
          .timeout(const Duration(seconds: 8));
      if (r.statusCode == 200 && r.body.trim().isNotEmpty) {
        _ouiCache[oui] = r.body.trim();
        return VendorResp(name: r.body.trim(), fromApi: true);
      }
      if (r.statusCode == 404) {
        return VendorResp(
          error: _isRandomMac(mac)
              ? 'MAC aleatório/privado (celulares modernos): não tem fabricante.'
              : 'Fabricante não encontrado na base.',
          fromApi: true,
        );
      }
      if (r.statusCode == 429) {
        return VendorResp(error: 'Limite da API atingido. Aguarde alguns segundos.', fromApi: true);
      }
      return VendorResp(error: 'Erro ${r.statusCode} na API.', fromApi: true);
    } catch (_) {
      return VendorResp(error: 'Sem conexão com a API (verifique a internet).');
    }
  }

  /// Consulta fabricantes dos dispositivos achados (API grátis: ~1 consulta/s).
  Future<void> _lookupVendors() async {
    if (!mounted) return;
    setState(() => _vendorBusy = true);
    for (final d in List<Device>.from(_devices)) {
      if (!mounted) return;
      if (d.mac == null || d.vendor != null) continue;
      final r = await _lookupVendor(d.mac!);
      if (r.name != null) {
        d.vendor = r.name;
        _evaluate(d);
        if (mounted) setState(_sortDevices);
      }
      if (r.fromApi) {
        await Future.delayed(Duration(milliseconds: r.error != null && r.error!.contains('Limite') ? 3000 : 1100));
      }
    }
    if (mounted) setState(() => _vendorBusy = false);
  }

  Future<void> _searchMac() async {
    final mac = _normalizeMac(_macCtl.text);
    if (mac == null) {
      _snack('Digite ao menos 6 dígitos hexadecimais (ex.: C0:56:E3).');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      _macBusy = true;
      _macResp = null;
      _macShown = mac;
    });
    final r = await _lookupVendor(mac);
    if (!mounted) return;
    setState(() {
      _macResp = r;
      _macBusy = false;
    });
  }

  // ============================================================
  //  4) WI-FIS SUSPEITOS
  // ============================================================
  List<WifiSus> _suspectWifis() {
    final out = <WifiSus>[];
    for (final ap in _aps) {
      var s = 0;
      final r = <String>[];
      if (ap.ssid.isNotEmpty && kSuspectSsid.hasMatch(ap.ssid)) {
        s += 50;
        r.add('Nome típico de câmera/IoT ("${ap.ssid}")');
        final open = !RegExp(r'WPA|WEP|PSK|SAE|EAP', caseSensitive: false).hasMatch(ap.capabilities);
        if (open) {
          s += 30;
          r.add('Rede aberta (sem senha)');
        }
      }
      if (ap.bssid.length >= 8) {
        final v = (kLocalOui[ap.bssid.substring(0, 8).toUpperCase()] ?? '').toLowerCase();
        if (kCameraVendors.any(v.contains)) {
          s += 35;
          r.add('Rádio de fabricante de câmeras');
        } else if (kIotVendors.any(v.contains)) {
          s += 30;
          r.add('Rádio de chip IoT (Espressif/ESP32)');
        }
      }
      if (s >= 30) out.add(WifiSus(ap.ssid.isEmpty ? '(oculta)' : ap.ssid, ap.bssid, ap.level, min(s, 100), r));
    }
    out.sort((a, b) => b.score.compareTo(a.score));
    return out;
  }

  // ============================================================
  //  5) VARREDURA BLUETOOTH (BLE)
  // ============================================================
  Future<void> _scanBle() async {
    if (_bleBusy) return;
    setState(() {
      _bleBusy = true;
      _ble = [];
      _bleMsg = null;
    });
    final found = <String, ScanResult>{};
    StreamSubscription<List<ScanResult>>? sub;
    try {
      await [Permission.bluetoothScan, Permission.bluetoothConnect, Permission.locationWhenInUse].request();
      if (await FlutterBluePlus.isSupported == false) {
        throw Exception('Este aparelho não suporta Bluetooth LE.');
      }
      sub = FlutterBluePlus.scanResults.listen((list) {
        for (final r in list) {
          found[r.device.remoteId.str] = r;
        }
      });
      await FlutterBluePlus.startScan(timeout: const Duration(seconds: 8));
      await Future.delayed(const Duration(milliseconds: 8500));
      await FlutterBluePlus.stopScan();
    } catch (e) {
      _bleMsg = 'Não foi possível escanear: ligue o Bluetooth e a Localização. ($e)';
    } finally {
      await sub?.cancel();
    }

    final list = <BleDev>[];
    for (final r in found.values) {
      var name = r.advertisementData.advName;
      if (name.isEmpty) name = r.device.platformName;
      final b = BleDev(r.device.remoteId.str, name, r.rssi);
      if (name.isNotEmpty && kBleSuspectName.hasMatch(name)) {
        b.score += 40;
        b.reasons.add('Nome sugere câmera/microfone/rastreador ("$name")');
      }
      if (r.advertisementData.manufacturerData.containsKey(0x02E5)) {
        b.score += 35;
        b.reasons.add('Chip Espressif (ESP32), comum em dispositivos DIY/espiões');
      }
      if (name.isEmpty && r.rssi > -55) {
        b.score += 10;
        b.reasons.add('Sem nome e muito próximo');
      }
      list.add(b);
    }
    list.sort((a, b) {
      final c = b.score.compareTo(a.score);
      return c != 0 ? c : b.rssi.compareTo(a.rssi);
    });
    if (!mounted) return;
    setState(() {
      _ble = list;
      _bleBusy = false;
      if (_bleMsg == null && list.isEmpty) _bleMsg = 'Nenhum dispositivo BLE encontrado.';
    });
  }

  // ============================================================
  //  6) RELATÓRIO
  // ============================================================
  String _buildReport() {
    String two(int n) => n.toString().padLeft(2, '0');
    final n = DateTime.now();
    final b = StringBuffer()
      ..writeln('RELATÓRIO - REDE SCANNER')
      ..writeln('${two(n.day)}/${two(n.month)}/${n.year} ${two(n.hour)}:${two(n.minute)}')
      ..writeln('Rede: ${_ssid ?? '-'}  |  IP deste aparelho: ${_myIp ?? '-'}')
      ..writeln();
    final alto = _devices.where((d) => d.risk == Risk.alto).length;
    final medio = _devices.where((d) => d.risk == Risk.medio).length;
    b.writeln('Dispositivos: ${_devices.length} (alto: $alto, médio: $medio, baixo: ${_devices.length - alto - medio})');
    if (!_firstRun && _scannedOnce) {
      b.writeln('Novos desde a última varredura: ${_devices.where((d) => d.isNew).length} | Sumiram: $_gone');
    }
    b.writeln();
    for (final d in _devices) {
      b.writeln('• ${d.ip} [${riskLabel(d.risk)} ${d.score}]${d.isNew ? ' (NOVO)' : ''}');
      b.writeln('  MAC: ${d.mac ?? '-'}  Fabricante: ${d.vendor ?? '-'}');
      if (d.openPorts.isNotEmpty) b.writeln('  Portas: ${(d.openPorts.toList()..sort()).join(', ')}');
      for (final r in d.reasons) {
        b.writeln('  - $r');
      }
    }
    final wifis = _suspectWifis();
    b.writeln('\nWi-Fis suspeitos: ${wifis.length}');
    for (final w in wifis) {
      b.writeln('• ${w.ssid} (${w.bssid}) ${w.level} dBm [${w.score}] - ${w.reasons.join('; ')}');
    }
    final bles = _ble.where((x) => x.score >= 30).toList();
    b.writeln('\nBluetooth suspeitos: ${bles.length}');
    for (final x in bles) {
      b.writeln('• ${x.name.isEmpty ? '(sem nome)' : x.name} ${x.id} ${x.rssi} dBm - ${x.reasons.join('; ')}');
    }
    return b.toString();
  }

  // ============================================================
  //  INTERFACE
  // ============================================================
  @override
  Widget build(BuildContext context) {
    final dark = Theme.of(context).brightness == Brightness.dark;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Rede Scanner'),
        actions: [
          IconButton(
            tooltip: 'Alternar tema',
            icon: Icon(dark ? Icons.light_mode : Icons.dark_mode),
            onPressed: () => themeMode.value = dark ? ThemeMode.light : ThemeMode.dark,
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
          children: [
            _signalCard(),
            const SizedBox(height: 16),
            _scanCard(),
            const SizedBox(height: 16),
            _wifiSuspectCard(),
            const SizedBox(height: 16),
            _bleCard(),
            const SizedBox(height: 16),
            _macCard(),
            const SizedBox(height: 16),
            _reportCard(),
          ],
        ),
      ),
    );
  }

  // Card base com título.
  Widget _card({required IconData icon, required String title, Widget? trailing, required Widget child}) {
    final cs = Theme.of(context).colorScheme;
    return Card(
      elevation: 0,
      color: cs.surfaceContainerLow,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(28)),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(icon, color: cs.primary),
              const SizedBox(width: 10),
              Expanded(child: Text(title, style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600))),
              if (trailing != null) trailing,
            ]),
            const SizedBox(height: 16),
            child,
          ],
        ),
      ),
    );
  }

  // ---------- Card de sinal ----------
  Widget _signalCard() {
    final rssi = _rssi;
    final pct = rssi == null ? 0 : (2 * (rssi + 100)).clamp(0, 100);
    String quality;
    Color color;
    if (rssi == null) {
      quality = 'Sem leitura';
      color = Colors.grey;
    } else if (rssi >= -50) {
      quality = 'Excelente';
      color = const Color(0xFF2E7D32);
    } else if (rssi >= -60) {
      quality = 'Muito bom';
      color = const Color(0xFF558B2F);
    } else if (rssi >= -70) {
      quality = 'Bom';
      color = const Color(0xFFF9A825);
    } else if (rssi >= -80) {
      quality = 'Fraco';
      color = const Color(0xFFEF6C00);
    } else {
      quality = 'Muito fraco';
      color = const Color(0xFFC62828);
    }

    return _card(
      icon: Icons.network_wifi,
      title: 'Sinal Wi-Fi deste aparelho',
      child: Column(children: [
        Row(children: [
          SizedBox(
            width: 104,
            height: 104,
            child: TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: pct / 100),
              duration: const Duration(milliseconds: 700),
              curve: Curves.easeOutCubic,
              builder: (_, v, __) => Stack(alignment: Alignment.center, children: [
                SizedBox.expand(
                  child: CircularProgressIndicator(
                    value: v,
                    strokeWidth: 10,
                    strokeCap: StrokeCap.round,
                    color: color,
                    backgroundColor: color.withAlpha(40),
                  ),
                ),
                Text('${(v * 100).round()}%', style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
              ]),
            ),
          ),
          const SizedBox(width: 20),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(_ssid ?? 'Sem Wi-Fi', style: Theme.of(context).textTheme.titleLarge, overflow: TextOverflow.ellipsis),
              const SizedBox(height: 4),
              Text(rssi == null ? '— dBm' : '$rssi dBm', style: TextStyle(fontSize: 18, color: color, fontWeight: FontWeight.w600)),
              Text(quality),
              const SizedBox(height: 8),
              Text('IP: ${_myIp ?? '-'}', style: Theme.of(context).textTheme.bodySmall),
            ]),
          ),
        ]),
        const SizedBox(height: 14),
        ClipRRect(
          borderRadius: BorderRadius.circular(8),
          child: LinearProgressIndicator(value: pct / 100, minHeight: 8, color: color, backgroundColor: color.withAlpha(40)),
        ),
        if (_gpsOff) ...[
          const SizedBox(height: 12),
          Row(children: [
            const Icon(Icons.location_off, size: 18, color: Color(0xFFEF6C00)),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                'Ative a Localização (GPS): o Android 7.1 exige para ler o Wi-Fi.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ]),
        ],
      ]),
    );
  }

  // ---------- Card de varredura ----------
  Widget _scanCard() {
    final cs = Theme.of(context).colorScheme;
    return _card(
      icon: Icons.radar,
      title: 'Varredura da rede local',
      trailing: _vendorBusy ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)) : null,
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            onPressed: _scanning ? null : _startScan,
            icon: const Icon(Icons.search),
            label: Text(_scanning ? 'Escaneando…' : 'Escanear rede'),
            style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 16)),
          ),
        ),
        if (_scanning) ...[
          const SizedBox(height: 14),
          ClipRRect(borderRadius: BorderRadius.circular(8), child: LinearProgressIndicator(value: _progress, minHeight: 8)),
          const SizedBox(height: 6),
          Text(_phase, style: Theme.of(context).textTheme.bodySmall),
        ],
        const SizedBox(height: 16),
        if (_scanning && _devices.isEmpty) ...[
          const Skeleton(),
          const SizedBox(height: 10),
          const Skeleton(),
          const SizedBox(height: 10),
          const Skeleton(),
        ] else if (_devices.isEmpty && _scannedOnce) ...[
          Text('Nenhum dispositivo respondeu.', style: TextStyle(color: cs.onSurfaceVariant)),
        ] else if (_devices.isNotEmpty) ...[
          _summaryChips(),
          if (_scannedOnce) ...[
            const SizedBox(height: 8),
            Text(
              _firstRun
                  ? 'Primeira varredura salva. Na próxima, aparelhos novos serão destacados.'
                  : 'Desde a última varredura: ${_devices.where((d) => d.isNew).length} novo(s), $_gone sumiram.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
          const SizedBox(height: 12),
          ..._devices.map(_deviceTile),
        ],
      ]),
    );
  }

  Widget _summaryChips() {
    Widget chip(Risk r) {
      final n = _devices.where((d) => d.risk == r).length;
      final c = riskColor(r);
      return Padding(
        padding: const EdgeInsets.only(right: 8),
        child: Chip(
          label: Text('${riskLabel(r)}: $n', style: TextStyle(color: c, fontWeight: FontWeight.w600)),
          backgroundColor: c.withAlpha(30),
          side: BorderSide(color: c.withAlpha(120)),
          visualDensity: VisualDensity.compact,
        ),
      );
    }

    return Wrap(children: [chip(Risk.alto), chip(Risk.medio), chip(Risk.baixo)]);
  }

  Widget _deviceTile(Device d) {
    final c = riskColor(d.risk);
    final st = vendorStyle(d.vendor);
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Container(
        decoration: BoxDecoration(
          color: c.withAlpha(28),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: c.withAlpha(90)),
        ),
        child: Theme(
          data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
          child: ExpansionTile(
            tilePadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 2),
            childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
            expandedCrossAxisAlignment: CrossAxisAlignment.start,
            leading: CircleAvatar(backgroundColor: st.color, child: Icon(st.icon, color: Colors.white)),
            title: Row(children: [
              Text(d.ip, style: const TextStyle(fontWeight: FontWeight.bold)),
              if (d.isNew) ...[
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(color: Colors.blue, borderRadius: BorderRadius.circular(8)),
                  child: const Text('NOVO', style: TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold)),
                ),
              ],
            ]),
            subtitle: Text(d.vendor ?? d.mac ?? 'Fabricante não identificado', maxLines: 1, overflow: TextOverflow.ellipsis),
            trailing: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(color: c, borderRadius: BorderRadius.circular(12)),
              child: Text('${riskLabel(d.risk)} ${d.score}', style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
            ),
            children: [
              _kv('Categoria', st.category),
              _kv('MAC', d.mac),
              _kv('Portas abertas', d.openPorts.isEmpty ? null : (d.openPorts.toList()..sort()).join(', ')),
              _kv('Título da página', d.webTitle),
              _kv('Servidor web', d.serverHeader),
              _kv('Realm do login', d.realm),
              _kv('RTSP', d.rtspConfirmed ? 'Confirmado${d.rtspServer != null ? ' - ${d.rtspServer}' : ''}' : null),
              _kv('ONVIF', d.onvifInfo),
              _kv('SSDP/UPnP', d.ssdpInfo),
              _kv('mDNS', d.mdnsInfo),
              if (d.reasons.isNotEmpty) ...[
                const SizedBox(height: 8),
                const Text('Motivos do risco', style: TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 4),
                ...d.reasons.map((r) => Padding(
                      padding: const EdgeInsets.only(bottom: 2),
                      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Icon(Icons.warning_amber_rounded, size: 16, color: c),
                        const SizedBox(width: 6),
                        Expanded(child: Text(r)),
                      ]),
                    )),
              ] else
                const Padding(
                  padding: EdgeInsets.only(top: 8),
                  child: Text('Nenhum indício de câmera encontrado.'),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _kv(String k, String? v) {
    if (v == null || v.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 3),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(width: 110, child: Text(k, style: TextStyle(color: Theme.of(context).colorScheme.onSurfaceVariant))),
        Expanded(child: Text(v)),
      ]),
    );
  }

  // ---------- Wi-Fis suspeitos ----------
  Widget _wifiSuspectCard() {
    final list = _suspectWifis();
    return _card(
      icon: Icons.wifi_find,
      title: 'Wi-Fis suspeitos próximos',
      trailing: Text('${_aps.length} redes', style: Theme.of(context).textTheme.bodySmall),
      child: list.isEmpty
          ? Text(_aps.isEmpty
              ? 'Aguardando leitura das redes (precisa de Localização ligada).'
              : 'Nenhuma rede com nome ou rádio típico de câmera.')
          : Column(
              children: list.map((w) {
                final c = riskColor(riskFromScore(w.score));
                return Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: c.withAlpha(28),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: c.withAlpha(90)),
                  ),
                  child: Row(children: [
                    Icon(Icons.wifi, color: c),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(w.ssid, style: const TextStyle(fontWeight: FontWeight.bold)),
                        Text('${w.bssid} • ${w.level} dBm', style: Theme.of(context).textTheme.bodySmall),
                        ...w.reasons.map((r) => Text('• $r', style: Theme.of(context).textTheme.bodySmall)),
                      ]),
                    ),
                    Text('${w.score}', style: TextStyle(color: c, fontWeight: FontWeight.bold, fontSize: 18)),
                  ]),
                );
              }).toList(),
            ),
    );
  }

  // ---------- Bluetooth ----------
  Widget _bleCard() {
    return _card(
      icon: Icons.bluetooth_searching,
      title: 'Bluetooth (BLE)',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(
          width: double.infinity,
          child: FilledButton.tonalIcon(
            onPressed: _bleBusy ? null : _scanBle,
            icon: const Icon(Icons.bluetooth),
            label: Text(_bleBusy ? 'Escaneando (8s)…' : 'Escanear Bluetooth'),
          ),
        ),
        if (_bleBusy) ...[
          const SizedBox(height: 12),
          const LinearProgressIndicator(),
        ],
        if (_bleMsg != null) ...[
          const SizedBox(height: 10),
          Text(_bleMsg!, style: Theme.of(context).textTheme.bodySmall),
        ],
        if (_ble.isNotEmpty) ...[
          const SizedBox(height: 12),
          ..._ble.take(15).map((b) {
            final c = riskColor(riskFromScore(b.score));
            return ListTile(
              contentPadding: EdgeInsets.zero,
              leading: CircleAvatar(backgroundColor: c.withAlpha(40), child: Icon(Icons.bluetooth, color: c)),
              title: Text(b.name.isEmpty ? '(sem nome)' : b.name),
              subtitle: Text('${b.id} • ${b.rssi} dBm${b.reasons.isEmpty ? '' : '\n${b.reasons.join('\n')}'}'),
              isThreeLine: b.reasons.isNotEmpty,
              trailing: b.score > 0 ? Text('${b.score}', style: TextStyle(color: c, fontWeight: FontWeight.bold)) : null,
            );
          }),
          if (_ble.length > 15) Text('+ ${_ble.length - 15} outros', style: Theme.of(context).textTheme.bodySmall),
        ],
      ]),
    );
  }

  // ---------- Busca de MAC ----------
  Widget _macCard() {
    final resp = _macResp;
    final st = vendorStyle(resp?.name);
    return _card(
      icon: Icons.fingerprint,
      title: 'Fabricante por MAC (OUI)',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        TextField(
          controller: _macCtl,
          inputFormatters: [MacFormatter()],
          textCapitalization: TextCapitalization.characters,
          onSubmitted: (_) => _searchMac(),
          decoration: InputDecoration(
            labelText: 'Endereço MAC',
            hintText: 'AA:BB:CC:DD:EE:FF',
            prefixIcon: const Icon(Icons.memory),
            filled: true,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(20), borderSide: BorderSide.none),
            suffixIcon: IconButton(icon: const Icon(Icons.search), onPressed: _macBusy ? null : _searchMac),
          ),
        ),
        const SizedBox(height: 8),
        Text('Funciona só com os 6 primeiros dígitos (ex.: C0:56:E3).', style: Theme.of(context).textTheme.bodySmall),
        if (_macBusy) ...[
          const SizedBox(height: 14),
          const LinearProgressIndicator(),
        ],
        if (resp != null) ...[
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: st.color.withAlpha(28),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: st.color.withAlpha(90)),
            ),
            child: Row(children: [
              CircleAvatar(radius: 26, backgroundColor: st.color, child: Icon(st.icon, color: Colors.white, size: 28)),
              const SizedBox(width: 14),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(resp.name ?? 'Não identificado', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                  if (resp.name != null) Text(st.category),
                  if (resp.error != null) Text(resp.error!, style: Theme.of(context).textTheme.bodySmall),
                  Text(_macShown ?? '', style: Theme.of(context).textTheme.bodySmall),
                ]),
              ),
            ]),
          ),
        ],
      ]),
    );
  }

  // ---------- Relatório ----------
  Widget _reportCard() {
    final enabled = _devices.isNotEmpty || _ble.isNotEmpty;
    return _card(
      icon: Icons.description_outlined,
      title: 'Relatório',
      child: Row(children: [
        Expanded(
          child: OutlinedButton.icon(
            onPressed: enabled
                ? () async {
                    await Clipboard.setData(ClipboardData(text: _buildReport()));
                    _snack('Relatório copiado.');
                  }
                : null,
            icon: const Icon(Icons.copy),
            label: const Text('Copiar'),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: FilledButton.icon(
            onPressed: enabled ? () => Share.share(_buildReport(), subject: 'Relatório Rede Scanner') : null,
            icon: const Icon(Icons.share),
            label: const Text('Compartilhar'),
          ),
        ),
      ]),
    );
  }
}
