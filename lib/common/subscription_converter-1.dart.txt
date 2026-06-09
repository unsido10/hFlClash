import 'dart:convert';
import 'dart:typed_data';

import 'yaml.dart';

enum SubscriptionSourceType { clashYaml, shareLinks, base64Links, happJson }

class SubscriptionConversionResult {
  final Uint8List bytes;
  final SubscriptionSourceType? sourceType;
  /// How many proxies were successfully imported (0 = passthrough / Clash YAML).
  final int imported;
  /// How many lines were skipped as malformed.
  final int skipped;

  const SubscriptionConversionResult({
    required this.bytes,
    this.sourceType,
    this.imported = 0,
    this.skipped = 0,
  });
}

class SubscriptionTextConversionResult {
  final String content;
  final SubscriptionSourceType sourceType;
  /// How many proxies were successfully imported (0 = passthrough / Clash YAML).
  final int imported;
  /// How many lines were skipped as malformed.
  final int skipped;

  const SubscriptionTextConversionResult({
    required this.content,
    required this.sourceType,
    this.imported = 0,
    this.skipped = 0,
  });
}

class SubscriptionConverter {
  static final _linkRegExp = RegExp(
    r'(?:(?:vless|vmess|trojan|ss|hysteria2|hy2|hysteria|tuic)://)[^\s]+',
    caseSensitive: false,
  );
  static final _linkSchemeRegExp = RegExp(
    r'(?:vless|vmess|trojan|ss|hysteria2|hy2|hysteria|tuic)://',
    caseSensitive: false,
  );
  static final _clashYamlRegExp = RegExp(
    r'^\s*(proxies|proxy-groups|proxy-providers|rules):\s*',
    multiLine: true,
  );

  Uint8List convertBytesIfNeeded(Uint8List bytes) {
    return convertBytes(bytes).bytes;
  }

  SubscriptionConversionResult convertBytes(Uint8List bytes) {
    final content = utf8.decode(bytes, allowMalformed: true);
    final converted = convertText(content);
    if (converted == null) {
      return SubscriptionConversionResult(bytes: bytes, sourceType: null);
    }
    return SubscriptionConversionResult(
      bytes: Uint8List.fromList(utf8.encode(converted.content)),
      sourceType: converted.sourceType,
      imported: converted.imported,
      skipped: converted.skipped,
    );
  }

  String? convertTextIfNeeded(String content) {
    return convertText(content)?.content;
  }

  SubscriptionTextConversionResult? convertText(String content) {
    final normalized = _normalizeText(_sanitize(content));
    if (normalized.isEmpty || _isClashYaml(normalized)) return null;

    final happJson = _tryConvertHappJson(normalized);
    if (happJson != null) return happJson;

    final rawLinks = _extractLinks(normalized);
    if (rawLinks.isNotEmpty) {
      return _convertLinks(rawLinks, SubscriptionSourceType.shareLinks);
    }

    final decoded = _decodeWholeBase64(normalized);
    if (decoded == null) return null;

    final base64HappJson = _tryConvertHappJson(decoded);
    if (base64HappJson != null) return base64HappJson;

    final links = _extractLinks(decoded);
    if (links.isEmpty) return null;
    return _convertLinks(links, SubscriptionSourceType.base64Links);
  }

  SubscriptionTextConversionResult? _convertLinks(
    List<String> links,
    SubscriptionSourceType sourceType,
  ) {
    final proxies = <Map<String, dynamic>>[];
    int skipped = 0;
    for (final link in links) {
      final proxy = _parseLink(link);
      if (proxy != null) {
        proxies.add(proxy);
      } else {
        skipped++;
      }
    }
    if (proxies.isEmpty) {
      throw 'Unsupported subscription links';
    }

    return SubscriptionTextConversionResult(
      content: _buildConfig(proxies),
      sourceType: sourceType,
      imported: proxies.length,
      skipped: skipped,
    );
  }

  String _buildConfig(List<Map<String, dynamic>> proxies) {
    _ensureUniqueNames(proxies);
    final proxyNames = proxies.map((proxy) => proxy['name'] as String).toList();
    final config = <String, dynamic>{
      'mixed-port': 7890,
      'allow-lan': false,
      'mode': 'rule',
      'log-level': 'info',
      'proxies': proxies,
      'proxy-groups': [
        {
          'name': 'PROXY',
          'type': 'select',
          'proxies': ['Auto', ...proxyNames, 'DIRECT'],
        },
        {
          'name': 'Auto',
          'type': 'url-test',
          'proxies': proxyNames,
          'url': 'http://www.gstatic.com/generate_204',
          'interval': 300,
        },
      ],
      'rules': ['MATCH,PROXY'],
    };
    return '${yaml.encode(config)}\n';
  }

  bool canConvert(String content) {
    return convertText(content) != null;
  }

  SubscriptionTextConversionResult? _tryConvertHappJson(String content) {
    final data = _tryDecodeJson(content);
    if (data == null) return null;
    final proxies = _parseHappJson(data);
    if (proxies.isEmpty) return null;
    return SubscriptionTextConversionResult(
      content: _buildConfig(proxies),
      sourceType: SubscriptionSourceType.happJson,
    );
  }

  Object? _tryDecodeJson(String content) {
    final trimmed = content.trimLeft();
    final first = trimmed.isEmpty ? null : trimmed[0];
    if (first != '[' && first != '{') return null;
    try {
      return json.decode(content);
    } catch (_) {
      return null;
    }
  }

  List<Map<String, dynamic>> _parseHappJson(Object data) {
    final items = data is List ? data : [data];
    final proxies = <Map<String, dynamic>>[];
    for (final item in items) {
      final profile = _asMap(item);
      if (profile == null) continue;
      final profileName = profile['remarks']?.toString().takeIfNotEmpty;
      final outbounds = profile['outbounds'];
      if (outbounds is! List) continue;
      for (final outbound in outbounds) {
        final outboundMap = _asMap(outbound);
        if (outboundMap == null) continue;
        final proxy = _parseHappOutbound(outboundMap, profileName);
        if (proxy != null) proxies.add(proxy);
      }
    }
    return proxies;
  }

  Map<String, dynamic>? _parseHappOutbound(
    Map<String, dynamic> outbound,
    String? profileName,
  ) {
    final protocol = outbound['protocol']?.toString().toLowerCase();
    return switch (protocol) {
      'vless' => _parseHappVlessOutbound(outbound, profileName),
      _ => null,
    };
  }

  Map<String, dynamic>? _parseHappVlessOutbound(
    Map<String, dynamic> outbound,
    String? profileName,
  ) {
    final settings = _asMap(outbound['settings']);
    final vnextList = settings?['vnext'];
    if (vnextList is! List || vnextList.isEmpty) return null;
    final vnext = _asMap(vnextList.first);
    if (vnext == null) return null;

    final server = vnext['address']?.toString();
    final port = _intValue(vnext['port']);
    final users = vnext['users'];
    if (server == null || server.isEmpty || port == null || users is! List) {
      return null;
    }
    Map<String, dynamic>? user;
    for (final item in users) {
      user = _asMap(item);
      if (user != null) break;
    }
    if (user == null) return null;
    final uuid = user['id']?.toString();
    if (uuid == null || uuid.isEmpty) return null;

    final tag = outbound['tag']?.toString().takeIfNotEmpty;
    final proxy = <String, dynamic>{
      'name': _happProxyName(profileName, tag, server, port),
      'type': 'vless',
      'server': server,
      'port': port,
      'uuid': uuid,
      'udp': true,
    };
    _putDynamic(proxy, 'flow', user['flow']);
    _putDynamic(proxy, 'encryption', user['encryption']);

    final stream = _asMap(outbound['streamSettings']);
    if (stream == null) return proxy;
    final security = stream['security']?.toString().toLowerCase();
    if (security == 'tls' || security == 'reality') {
      proxy['tls'] = true;
    }

    final tls = _asMap(stream['tlsSettings']);
    if (tls != null) {
      _putDynamic(proxy, 'servername', tls['serverName']);
      _putDynamic(proxy, 'client-fingerprint', tls['fingerprint']);
      final alpn = _stringList(tls['alpn']);
      if (alpn.isNotEmpty) proxy['alpn'] = alpn;
      if (tls['allowInsecure'] == true) {
        proxy['skip-cert-verify'] = true;
      }
    }

    final reality = _asMap(stream['realitySettings']);
    if (reality != null) {
      _putDynamic(proxy, 'servername', reality['serverName']);
      _putDynamic(proxy, 'client-fingerprint', reality['fingerprint']);
      final realityOpts = <String, dynamic>{};
      _putDynamic(realityOpts, 'public-key', reality['publicKey']);
      _putDynamic(realityOpts, 'short-id', reality['shortId']);
      _putDynamic(realityOpts, 'spider-x', reality['spiderX']);
      if (realityOpts.isNotEmpty) proxy['reality-opts'] = realityOpts;
    }

    final network = stream['network']?.toString();
    if (network == null || network.isEmpty || network == 'tcp') return proxy;
    proxy['network'] = network;
    switch (network) {
      case 'grpc':
        final grpc = _asMap(stream['grpcSettings']);
        _applyGrpc(proxy, grpc?['serviceName']?.toString());
        break;
      case 'ws':
      case 'httpupgrade':
        final ws =
            _asMap(stream['wsSettings']) ??
            _asMap(stream['httpupgradeSettings']);
        _applyWs(
          proxy,
          ws?['path']?.toString(),
          _hostFromHeaders(ws?['headers']) ?? ws?['host']?.toString(),
          httpUpgrade: network == 'httpupgrade',
        );
        break;
      case 'xhttp':
        _applyXhttpSettings(proxy, _asMap(stream['xhttpSettings']));
        break;
      case 'h2':
        final http = _asMap(stream['httpSettings']);
        final h2Opts = <String, dynamic>{};
        _putDynamic(h2Opts, 'path', http?['path']);
        final hosts = _stringList(http?['host']);
        if (hosts.isNotEmpty) h2Opts['host'] = hosts;
        if (h2Opts.isNotEmpty) proxy['h2-opts'] = h2Opts;
        break;
    }
    return proxy;
  }

  String _happProxyName(
    String? profileName,
    String? tag,
    String server,
    int port,
  ) {
    final base = profileName?.takeIfNotEmpty ?? 'vless-$server:$port';
    if (tag == null || tag == 'proxy') return base;
    return '$base $tag';
  }

  List<String> _extractLinks(String content) {
    final links = <String>[];
    for (final line in content.split(RegExp(r'\r?\n'))) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      final matches = _linkSchemeRegExp.allMatches(trimmed).toList();
      if (matches.isEmpty) continue;
      for (var i = 0; i < matches.length; i++) {
        final start = matches[i].start;
        final end = i + 1 < matches.length
            ? matches[i + 1].start
            : trimmed.length;
        links.add(_normalizeLinkText(trimmed.substring(start, end)));
      }
    }
    if (links.isNotEmpty) return links;
    return _linkRegExp.allMatches(content).map((match) {
      return _normalizeLinkText(match.group(0)!);
    }).toList();
  }

  String _normalizeLinkText(String link) {
    return link.trim().trimRightChar(',').replaceAll('&amp;', '&');
  }

  Map<String, dynamic>? _parseLink(String link) {
    final normalizedLink = _normalizeLinkForUri(link);
    final scheme = normalizedLink.split('://').first.toLowerCase();
    try {
      return switch (scheme) {
        'vless' => _parseVless(normalizedLink),
        'vmess' => _parseVmess(normalizedLink),
        'trojan' => _parseTrojan(normalizedLink),
        'ss' => _parseShadowsocks(normalizedLink),
        'hysteria2' || 'hy2' => _parseHysteria2(normalizedLink),
        'hysteria' => _parseHysteria(normalizedLink),
        'tuic' => _parseTuic(normalizedLink),
        _ => null,
      };
    } catch (_) {
      return null;
    }
  }

  String _normalizeLinkForUri(String link) {
    final index = link.indexOf('#');
    if (index == -1) return link;
    final fragment = link.substring(index + 1);
    String decoded;
    try {
      decoded = Uri.decodeComponent(fragment);
    } catch (_) {
      decoded = fragment;
    }
    return '${link.substring(0, index)}#${Uri.encodeComponent(decoded)}';
  }

  Map<String, dynamic>? _parseVless(String link) {
    final uri = Uri.tryParse(link);
    if (!_hasServer(uri)) return null;
    final params = uri!.queryParameters;
    final port = _port(uri);
    final uuid = _decode(uri.userInfo);
    if (port == null || uuid.isEmpty) return null;

    final proxy = <String, dynamic>{
      'name': _name(uri, 'vless-${uri.host}:$port'),
      'type': 'vless',
      'server': uri.host,
      'port': port,
      'uuid': uuid,
      'udp': true,
    };
    _put(proxy, 'flow', params['flow']);
    _put(proxy, 'encryption', params['encryption']);

    final security = params['security']?.toLowerCase();
    if (security == 'tls' || security == 'reality' || _truthy(params['tls'])) {
      proxy['tls'] = true;
    }
    _put(
      proxy,
      'servername',
      _first(params, ['sni', 'servername', 'serverName']),
    );
    _put(proxy, 'client-fingerprint', params['fp']);
    _putList(proxy, 'alpn', params['alpn']);
    _putTruthy(
      proxy,
      'skip-cert-verify',
      _first(params, ['allowInsecure', 'insecure']),
    );

    if (security == 'reality') {
      final realityOpts = <String, dynamic>{};
      _put(realityOpts, 'public-key', _first(params, ['pbk', 'public-key']));
      _put(realityOpts, 'short-id', _first(params, ['sid', 'short-id']));
      _put(realityOpts, 'spider-x', _first(params, ['spx', 'spiderX']));
      if (realityOpts.isNotEmpty) proxy['reality-opts'] = realityOpts;
    }

    _applyTransport(proxy, params);
    return proxy;
  }

  Map<String, dynamic>? _parseVmess(String link) {
    final raw = link.substring('vmess://'.length).trim();
    final decoded = _decodeBase64(raw);
    if (decoded == null) return null;
    final data = json.decode(decoded) as Map<String, dynamic>;
    final server = data['add']?.toString();
    final port = int.tryParse(data['port']?.toString() ?? '');
    final uuid = data['id']?.toString();
    if (server == null || server.isEmpty || port == null || uuid == null) {
      return null;
    }

    final proxy = <String, dynamic>{
      'name': data['ps']?.toString().takeIfNotEmpty ?? 'vmess-$server:$port',
      'type': 'vmess',
      'server': server,
      'port': port,
      'uuid': uuid,
      'alterId': int.tryParse(data['aid']?.toString() ?? '') ?? 0,
      'cipher': data['scy']?.toString().takeIfNotEmpty ?? 'auto',
      'udp': true,
    };
    final tls = data['tls']?.toString().toLowerCase();
    if (tls == 'tls') proxy['tls'] = true;
    _put(proxy, 'servername', data['sni']?.toString());
    _put(proxy, 'client-fingerprint', data['fp']?.toString());
    _putList(proxy, 'alpn', data['alpn']?.toString());

    final network = data['net']?.toString();
    if (network != null && network.isNotEmpty && network != 'tcp') {
      proxy['network'] = network;
      if (network == 'ws') {
        _applyWs(proxy, data['path']?.toString(), data['host']?.toString());
      } else if (network == 'grpc') {
        _applyGrpc(proxy, data['path']?.toString());
      } else if (network == 'xhttp') {
        _applyXhttp(
          proxy,
          data.map((key, value) => MapEntry(key, value?.toString() ?? '')),
        );
      }
    }
    return proxy;
  }

  Map<String, dynamic>? _parseTrojan(String link) {
    final uri = Uri.tryParse(link);
    if (!_hasServer(uri)) return null;
    final params = uri!.queryParameters;
    final port = _port(uri);
    final password = _decode(uri.userInfo);
    if (port == null || password.isEmpty) return null;

    final proxy = <String, dynamic>{
      'name': _name(uri, 'trojan-${uri.host}:$port'),
      'type': 'trojan',
      'server': uri.host,
      'port': port,
      'password': password,
      'udp': true,
    };
    _put(proxy, 'sni', _first(params, ['sni', 'peer', 'servername']));
    _putList(proxy, 'alpn', params['alpn']);
    _putTruthy(
      proxy,
      'skip-cert-verify',
      _first(params, ['allowInsecure', 'insecure']),
    );
    _applyTransport(proxy, params);
    return proxy;
  }

  Map<String, dynamic>? _parseShadowsocks(String link) {
    final uri = Uri.tryParse(link);
    if (uri == null) return null;
    final params = uri.queryParameters;
    var server = uri.host;
    var port = _port(uri);
    var credentials = _decode(uri.userInfo);

    if (credentials.isEmpty || !credentials.contains(':')) {
      credentials = _decodeBase64(credentials) ?? credentials;
    }

    if (server.isEmpty || port == null || !credentials.contains(':')) {
      final withoutScheme = link.substring('ss://'.length);
      final beforeMeta = withoutScheme.split(RegExp(r'[?#]')).first;
      final decoded = _decodeBase64(beforeMeta);
      final parsed = decoded == null ? null : _parseCredentialServer(decoded);
      if (parsed == null) return null;
      credentials = parsed.credentials;
      server = parsed.server;
      port = parsed.port;
    }

    final splitIndex = credentials.indexOf(':');
    final cipher = credentials.substring(0, splitIndex);
    final password = credentials.substring(splitIndex + 1);
    if (cipher.isEmpty || password.isEmpty || server.isEmpty) {
      return null;
    }

    final proxy = <String, dynamic>{
      'name': _name(uri, 'ss-$server:$port'),
      'type': 'ss',
      'server': server,
      'port': port,
      'cipher': cipher,
      'password': password,
      'udp': true,
    };
    _applyShadowsocksPlugin(proxy, params['plugin']);
    return proxy;
  }

  Map<String, dynamic>? _parseHysteria2(String link) {
    final uri = Uri.tryParse(link);
    if (!_hasServer(uri)) return null;
    final params = uri!.queryParameters;
    final port = _port(uri);
    final password = _decode(uri.userInfo).takeIfNotEmpty ?? params['auth'];
    if (port == null || password == null || password.isEmpty) return null;

    final proxy = <String, dynamic>{
      'name': _name(uri, 'hysteria2-${uri.host}:$port'),
      'type': 'hysteria2',
      'server': uri.host,
      'port': port,
      'password': password,
      'udp': true,
    };
    _put(proxy, 'sni', _first(params, ['sni', 'peer']));
    _put(proxy, 'obfs', params['obfs']);
    _put(
      proxy,
      'obfs-password',
      _first(params, ['obfs-password', 'obfs_password']),
    );
    _put(proxy, 'up', _first(params, ['up', 'upmbps']));
    _put(proxy, 'down', _first(params, ['down', 'downmbps']));
    _putList(proxy, 'alpn', params['alpn']);
    _putTruthy(
      proxy,
      'skip-cert-verify',
      _first(params, ['allowInsecure', 'insecure']),
    );
    return proxy;
  }

  Map<String, dynamic>? _parseHysteria(String link) {
    final uri = Uri.tryParse(link);
    if (!_hasServer(uri)) return null;
    final params = uri!.queryParameters;
    final port = _port(uri);
    if (port == null) return null;

    final auth =
        _first(params, ['auth', 'auth-str', 'auth_str']) ??
        _decode(uri.userInfo).takeIfNotEmpty;
    final proxy = <String, dynamic>{
      'name': _name(uri, 'hysteria-${uri.host}:$port'),
      'type': 'hysteria',
      'server': uri.host,
      'port': port,
      'udp': true,
    };
    _put(proxy, 'auth-str', auth);
    _put(proxy, 'protocol', params['protocol']);
    _put(proxy, 'obfs', params['obfs']);
    _put(proxy, 'sni', _first(params, ['sni', 'peer']));
    _put(proxy, 'up', _first(params, ['up', 'upmbps']));
    _put(proxy, 'down', _first(params, ['down', 'downmbps']));
    _putList(proxy, 'alpn', params['alpn']);
    _putTruthy(
      proxy,
      'skip-cert-verify',
      _first(params, ['allowInsecure', 'insecure']),
    );
    return proxy;
  }

  Map<String, dynamic>? _parseTuic(String link) {
    final uri = Uri.tryParse(link);
    if (!_hasServer(uri)) return null;
    final params = uri!.queryParameters;
    final port = _port(uri);
    final userInfo = _decode(uri.userInfo);
    final separator = userInfo.indexOf(':');
    if (port == null || separator == -1) return null;

    final proxy = <String, dynamic>{
      'name': _name(uri, 'tuic-${uri.host}:$port'),
      'type': 'tuic',
      'server': uri.host,
      'port': port,
      'uuid': userInfo.substring(0, separator),
      'password': userInfo.substring(separator + 1),
      'udp': true,
    };
    _put(proxy, 'sni', _first(params, ['sni', 'servername']));
    _put(
      proxy,
      'congestion-controller',
      _first(params, [
        'congestion_control',
        'congestion-controller',
        'congestion',
      ]),
    );
    _put(
      proxy,
      'udp-relay-mode',
      _first(params, ['udp_relay_mode', 'udp-relay-mode']),
    );
    _putList(proxy, 'alpn', params['alpn']);
    _putTruthy(
      proxy,
      'disable-sni',
      _first(params, ['disable_sni', 'disable-sni']),
    );
    _putTruthy(
      proxy,
      'reduce-rtt',
      _first(params, ['reduce_rtt', 'reduce-rtt']),
    );
    return proxy;
  }

  void _applyTransport(Map<String, dynamic> proxy, Map<String, String> params) {
    final network = _first(params, ['type', 'network']);
    if (network == null || network.isEmpty || network == 'tcp') return;
    proxy['network'] = network;
    if (network == 'ws' || network == 'httpupgrade') {
      _applyWs(
        proxy,
        params['path'],
        _first(params, ['host', 'Host']),
        httpUpgrade: network == 'httpupgrade',
        earlyData: params['ed'],
        earlyDataHeader: params['eh'],
      );
    } else if (network == 'grpc') {
      _applyGrpc(
        proxy,
        _first(params, ['serviceName', 'service-name', 'grpc-service-name']),
      );
    } else if (network == 'xhttp') {
      _applyXhttp(proxy, params);
    } else if (network == 'h2') {
      final h2Opts = <String, dynamic>{};
      _put(h2Opts, 'path', params['path']);
      _putList(h2Opts, 'host', _first(params, ['host', 'Host']));
      if (h2Opts.isNotEmpty) proxy['h2-opts'] = h2Opts;
    }
  }

  void _applyWs(
    Map<String, dynamic> proxy,
    String? path,
    String? host, {
    bool httpUpgrade = false,
    String? earlyData,
    String? earlyDataHeader,
  }) {
    final wsOpts = <String, dynamic>{};
    _put(wsOpts, 'path', path);
    if (host != null && host.isNotEmpty) {
      wsOpts['headers'] = {'Host': host};
    }
    if (httpUpgrade) {
      wsOpts['v2ray-http-upgrade'] = true;
    }
    final maxEarlyData = int.tryParse(earlyData ?? '');
    if (maxEarlyData != null) {
      if (httpUpgrade) {
        wsOpts['v2ray-http-upgrade-fast-open'] = true;
      } else {
        wsOpts['max-early-data'] = maxEarlyData;
        wsOpts['early-data-header-name'] = 'Sec-WebSocket-Protocol';
      }
    }
    _put(wsOpts, 'early-data-header-name', earlyDataHeader);
    if (wsOpts.isNotEmpty) proxy['ws-opts'] = wsOpts;
  }

  void _applyGrpc(Map<String, dynamic> proxy, String? serviceName) {
    if (serviceName == null || serviceName.isEmpty) return;
    proxy['grpc-opts'] = {'grpc-service-name': serviceName};
  }

  void _applyXhttp(Map<String, dynamic> proxy, Map<String, String> params) {
    final opts = <String, dynamic>{};
    _put(opts, 'path', params['path']);
    _put(opts, 'host', _first(params, ['host', 'Host']));
    _put(opts, 'mode', params['mode']);

    final headers = _parseHeaders(params['headers']);
    if (headers != null) {
      opts['headers'] = headers;
    }

    _putTruthy(
      opts,
      'no-grpc-header',
      _first(params, ['noGRPCHeader', 'no-grpc-header', 'noGrpcHeader']),
    );
    _put(
      opts,
      'x-padding-bytes',
      _first(params, ['xPaddingBytes', 'x-padding-bytes']),
    );
    _putBoolIfPresent(
      opts,
      'x-padding-obfs-mode',
      _first(params, ['xPaddingObfsMode', 'x-padding-obfs-mode']),
    );
    _put(
      opts,
      'x-padding-key',
      _first(params, ['xPaddingKey', 'x-padding-key']),
    );
    _put(
      opts,
      'x-padding-header',
      _first(params, ['xPaddingHeader', 'x-padding-header']),
    );
    _put(
      opts,
      'x-padding-placement',
      _first(params, ['xPaddingPlacement', 'x-padding-placement']),
    );
    _put(
      opts,
      'x-padding-method',
      _first(params, ['xPaddingMethod', 'x-padding-method']),
    );
    _put(
      opts,
      'uplink-http-method',
      _first(params, ['uplinkHttpMethod', 'uplink-http-method']),
    );
    _put(
      opts,
      'session-placement',
      _first(params, ['sessionPlacement', 'session-placement']),
    );
    _put(opts, 'session-key', _first(params, ['sessionKey', 'session-key']));
    _put(
      opts,
      'seq-placement',
      _first(params, ['seqPlacement', 'seq-placement']),
    );
    _put(opts, 'seq-key', _first(params, ['seqKey', 'seq-key']));
    _put(
      opts,
      'uplink-data-placement',
      _first(params, ['uplinkDataPlacement', 'uplink-data-placement']),
    );
    _put(
      opts,
      'uplink-data-key',
      _first(params, ['uplinkDataKey', 'uplink-data-key']),
    );
    _putInt(
      opts,
      'uplink-chunk-size',
      _first(params, ['uplinkChunkSize', 'uplink-chunk-size']),
    );
    _putInt(
      opts,
      'sc-max-each-post-bytes',
      _first(params, ['scMaxEachPostBytes', 'sc-max-each-post-bytes']),
    );
    _putInt(
      opts,
      'sc-min-posts-interval-ms',
      _first(params, ['scMinPostsIntervalMs', 'sc-min-posts-interval-ms']),
    );

    final extra = _parseJsonMap(params['extra']);
    if (extra != null) {
      _applyXhttpExtra(extra, opts);
    }

    proxy['xhttp-opts'] = opts;
  }

  void _applyXhttpSettings(
    Map<String, dynamic> proxy,
    Map<String, dynamic>? settings,
  ) {
    final opts = <String, dynamic>{};
    if (settings != null) {
      _putDynamic(opts, 'path', settings['path']);
      _putDynamic(opts, 'host', settings['host']);
      _putDynamic(opts, 'mode', settings['mode']);
      final headers = _asStringMap(settings['headers']);
      if (headers != null) opts['headers'] = headers;
      final extra = _asMap(settings['extra']);
      if (extra != null) _applyXhttpExtra(extra, opts);
    }
    proxy['xhttp-opts'] = opts;
  }

  void _applyXhttpExtra(Map<String, dynamic> extra, Map<String, dynamic> opts) {
    if (extra['noGRPCHeader'] == true) {
      opts['no-grpc-header'] = true;
    }
    _putDynamic(opts, 'x-padding-bytes', extra['xPaddingBytes']);
    _putDynamic(opts, 'x-padding-obfs-mode', extra['xPaddingObfsMode']);
    _putDynamic(opts, 'x-padding-key', extra['xPaddingKey']);
    _putDynamic(opts, 'x-padding-header', extra['xPaddingHeader']);
    _putDynamic(opts, 'x-padding-placement', extra['xPaddingPlacement']);
    _putDynamic(opts, 'x-padding-method', extra['xPaddingMethod']);
    _putDynamic(opts, 'uplink-http-method', extra['uplinkHttpMethod']);
    _putDynamic(opts, 'session-placement', extra['sessionPlacement']);
    _putDynamic(opts, 'session-key', extra['sessionKey']);
    _putDynamic(opts, 'seq-placement', extra['seqPlacement']);
    _putDynamic(opts, 'seq-key', extra['seqKey']);
    _putDynamic(opts, 'uplink-data-placement', extra['uplinkDataPlacement']);
    _putDynamic(opts, 'uplink-data-key', extra['uplinkDataKey']);
    _putPositiveDynamic(opts, 'uplink-chunk-size', extra['uplinkChunkSize']);
    _putPositiveDynamic(
      opts,
      'sc-max-each-post-bytes',
      extra['scMaxEachPostBytes'],
    );
    _putPositiveDynamic(
      opts,
      'sc-min-posts-interval-ms',
      extra['scMinPostsIntervalMs'],
    );

    final xmux = _asMap(extra['xmux']);
    if (xmux != null) {
      final reuseSettings = _xhttpReuseSettings(xmux);
      if (reuseSettings.isNotEmpty) {
        opts['reuse-settings'] = reuseSettings;
      }
    }

    final downloadSettings = _xhttpDownloadSettings(
      _asMap(extra['downloadSettings']),
    );
    if (downloadSettings != null) {
      opts['download-settings'] = downloadSettings;
    }
  }

  Map<String, dynamic>? _xhttpDownloadSettings(Map<String, dynamic>? data) {
    if (data == null) return null;
    final result = <String, dynamic>{};
    _putDynamic(result, 'server', data['address']);
    _putDynamic(result, 'port', data['port']);

    final security = data['security']?.toString().toLowerCase();
    if (security == 'tls' || security == 'reality') {
      result['tls'] = true;
      final tls = _asMap(data['tlsSettings']);
      if (tls != null) {
        _putDynamic(result, 'servername', tls['serverName']);
        _putDynamic(result, 'client-fingerprint', tls['fingerprint']);
        final alpn = _stringList(tls['alpn']);
        if (alpn.isNotEmpty) result['alpn'] = alpn;
        if (tls['allowInsecure'] == true) {
          result['skip-cert-verify'] = true;
        }
      }
      if (security == 'reality') {
        final reality = _asMap(data['realitySettings']);
        if (reality != null) {
          final realityOpts = <String, dynamic>{};
          _putDynamic(realityOpts, 'public-key', reality['publicKey']);
          _putDynamic(realityOpts, 'short-id', reality['shortId']);
          if (realityOpts.isNotEmpty) {
            result['reality-opts'] = realityOpts;
          }
        }
      }
    }

    final xhttp = _asMap(data['xhttpSettings']);
    if (xhttp != null) {
      _putDynamic(result, 'path', xhttp['path']);
      _putDynamic(result, 'host', xhttp['host']);
      final headers = _asStringMap(xhttp['headers']);
      if (headers != null) result['headers'] = headers;

      final extra = _asMap(xhttp['extra']);
      final xmux = extra == null ? null : _asMap(extra['xmux']);
      if (xmux != null) {
        final reuseSettings = _xhttpReuseSettings(xmux);
        if (reuseSettings.isNotEmpty) {
          result['reuse-settings'] = reuseSettings;
        }
      }
    }

    return result.isEmpty ? null : result;
  }

  Map<String, dynamic> _xhttpReuseSettings(Map<String, dynamic> xmux) {
    final result = <String, dynamic>{};
    _putDynamic(result, 'max-connections', xmux['maxConnections']);
    _putDynamic(result, 'max-concurrency', xmux['maxConcurrency']);
    _putDynamic(result, 'c-max-reuse-times', xmux['cMaxReuseTimes']);
    _putDynamic(result, 'h-max-request-times', xmux['hMaxRequestTimes']);
    _putDynamic(result, 'h-max-reusable-secs', xmux['hMaxReusableSecs']);
    _putDynamic(result, 'h-keep-alive-period', xmux['hKeepAlivePeriod']);
    return result;
  }

  void _applyShadowsocksPlugin(Map<String, dynamic> proxy, String? plugin) {
    if (plugin == null || plugin.isEmpty) return;
    final parts = plugin.split(';');
    final name = parts.first;
    final options = <String, String>{};
    for (final part in parts.skip(1)) {
      final index = part.indexOf('=');
      if (index == -1) continue;
      options[part.substring(0, index)] = part.substring(index + 1);
    }
    if (name == 'obfs-local' || name == 'simple-obfs') {
      proxy['plugin'] = 'obfs';
      proxy['plugin-opts'] = {
        if (options['obfs'] != null) 'mode': options['obfs'],
        if (options['obfs-host'] != null) 'host': options['obfs-host'],
      };
    } else if (name == 'v2ray-plugin') {
      proxy['plugin'] = name;
      proxy['plugin-opts'] = {
        if (options['mode'] != null) 'mode': options['mode'],
        if (options['host'] != null) 'host': options['host'],
        if (options['path'] != null) 'path': options['path'],
        if (_truthy(options['tls'])) 'tls': true,
        if (_truthy(options['mux'])) 'mux': true,
      };
    }
  }

  void _ensureUniqueNames(List<Map<String, dynamic>> proxies) {
    final used = <String, int>{};
    for (final proxy in proxies) {
      final raw = (proxy['name'] as String?)?.trim();
      final name = raw == null || raw.isEmpty ? 'Proxy' : raw;
      final count = used[name] ?? 0;
      used[name] = count + 1;
      proxy['name'] = count == 0 ? name : '$name ${count + 1}';
    }
  }

  /// Sanitises raw subscription content before format detection.
  ///
  /// 1. Decodes HTML entities (`&amp;`, `&amp%3B`).
  /// 2. Removes lines where an `extra={...}` JSON object is not closed.
  /// 3. Compacts spaced JSON key-value pairs inside URI parameters so that
  ///    the YAML parser does not misinterpret `: ` as a mapping indicator.
  String _sanitize(String content) {
    // 1. HTML entity decoding.
    var s = content
        .replaceAll('&amp;', '&')
        .replaceAll('&amp%3B', '&')
        .replaceAll('%3B', ';');

    // 2. Drop lines with unclosed extra={...} JSON.
    final lines = s.split('\n');
    final cleaned = <String>[];
    for (final line in lines) {
      final t = line.trim();
      if (t.isEmpty) {
        cleaned.add(line);
        continue;
      }
      if (t.contains('extra={') || t.contains('extra%3D%7B')) {
        final open = t.split('{').length - 1;
        final close = t.split('}').length - 1;
        if (open > close) continue; // unbalanced – malformed
      }
      cleaned.add(line);
    }
    s = cleaned.join('\n');

    // 3. Compact spaced JSON inside URI query strings:
    //    "key": "value"  →  "key":"value"
    s = s.replaceAllMapped(
      RegExp(r'"(\w[\w-]*)"\s*:\s*"([^"]*)"'),
      (m) => '"${m[1]}":"${m[2]}"',
    );

    return s;
  }

  String _normalizeText(String content) {
    return content.replaceFirst('\uFEFF', '').trim();
  }

  bool _isClashYaml(String content) {
    return _clashYamlRegExp.hasMatch(content);
  }

  String? _decodeWholeBase64(String content) {
    final normalized = content.replaceAll(RegExp(r'\s+'), '');
    if (normalized.length < 16 ||
        !RegExp(r'^[A-Za-z0-9+/=_-]+$').hasMatch(normalized)) {
      return null;
    }
    final decoded = _decodeBase64(normalized);
    if (decoded == null) return null;
    if (_extractLinks(decoded).isEmpty && _tryDecodeJson(decoded) == null) {
      return null;
    }
    return decoded;
  }

  String? _decodeBase64(String value) {
    if (value.isEmpty) return null;
    try {
      var normalized = value.replaceAll('-', '+').replaceAll('_', '/');
      final remainder = normalized.length % 4;
      if (remainder != 0) {
        normalized = normalized.padRight(
          normalized.length + 4 - remainder,
          '=',
        );
      }
      final decoded = utf8.decode(base64.decode(normalized));
      if (_hasUnsafeControl(decoded)) return null;
      return decoded;
    } catch (_) {
      return null;
    }
  }

  _ParsedShadowsocks? _parseCredentialServer(String value) {
    final atIndex = value.lastIndexOf('@');
    final colonIndex = value.lastIndexOf(':');
    if (atIndex == -1 || colonIndex <= atIndex) return null;
    final port = int.tryParse(value.substring(colonIndex + 1));
    if (port == null) return null;
    return _ParsedShadowsocks(
      credentials: value.substring(0, atIndex),
      server: value.substring(atIndex + 1, colonIndex),
      port: port,
    );
  }

  bool _hasServer(Uri? uri) {
    return uri != null && uri.host.isNotEmpty;
  }

  int? _port(Uri uri) {
    return uri.hasPort ? uri.port : null;
  }

  int? _intValue(Object? value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    if (value is String) return int.tryParse(value);
    return null;
  }

  String? _hostFromHeaders(Object? value) {
    final headers = _asStringMap(value);
    if (headers == null) return null;
    return headers['Host'] ?? headers['host'];
  }

  String _name(Uri uri, String fallback) {
    return _decode(uri.fragment).takeIfNotEmpty ?? fallback;
  }

  String _decode(String value) {
    try {
      return _cleanString(Uri.decodeComponent(value));
    } catch (_) {
      return _cleanString(value);
    }
  }

  String? _first(Map<String, String> params, List<String> keys) {
    for (final key in keys) {
      final value = params[key];
      if (value != null && value.isNotEmpty) return value;
    }
    return null;
  }

  void _put(Map<String, dynamic> target, String key, String? value) {
    if (value == null || value.isEmpty) return;
    final cleaned = _cleanString(value);
    if (cleaned.isNotEmpty) target[key] = cleaned;
  }

  void _putDynamic(Map<String, dynamic> target, String key, Object? value) {
    if (value == null) return;
    if (value is String) {
      final cleaned = _cleanString(value);
      if (cleaned.isEmpty) return;
      target[key] = cleaned;
      return;
    }
    target[key] = value;
  }

  void _putInt(Map<String, dynamic> target, String key, String? value) {
    if (value == null || value.isEmpty) return;
    final intValue = int.tryParse(value);
    if (intValue != null && intValue > 0) {
      target[key] = intValue;
    }
  }

  void _putPositiveDynamic(
    Map<String, dynamic> target,
    String key,
    Object? value,
  ) {
    final intValue = _intValue(value);
    if (intValue != null && intValue > 0) {
      target[key] = intValue;
    }
  }

  void _putBoolIfPresent(
    Map<String, dynamic> target,
    String key,
    String? value,
  ) {
    final boolValue = _boolValue(value);
    if (boolValue != null) {
      target[key] = boolValue;
    }
  }

  void _putList(Map<String, dynamic> target, String key, String? value) {
    if (value == null || value.isEmpty) return;
    target[key] = value
        .split(',')
        .map((item) => item.trim())
        .where((item) => item.isNotEmpty)
        .toList();
  }

  void _putTruthy(Map<String, dynamic> target, String key, String? value) {
    if (_truthy(value)) target[key] = true;
  }

  Map<String, dynamic>? _parseJsonMap(String? value) {
    if (value == null || value.isEmpty) return null;
    try {
      return _asMap(json.decode(value));
    } catch (_) {
      return null;
    }
  }

  bool _hasUnsafeControl(String value) {
    return value.codeUnits.any((code) {
      return code < 32 && code != 9 && code != 10 && code != 13;
    });
  }

  String _cleanString(String value) {
    return String.fromCharCodes(
      value.codeUnits.where((code) {
        return code >= 32 || code == 9 || code == 10 || code == 13;
      }),
    );
  }

  Map<String, String>? _parseHeaders(String? value) {
    if (value == null || value.isEmpty) return null;
    try {
      final headers = _asStringMap(json.decode(value));
      if (headers != null) return headers;
    } catch (_) {}

    final headers = <String, String>{};
    for (final item in value.split(RegExp(r'[,;|]'))) {
      final separator = item.contains(':') ? ':' : '=';
      final index = item.indexOf(separator);
      if (index == -1) continue;
      final key = item.substring(0, index).trim();
      final headerValue = item.substring(index + 1).trim();
      if (key.isNotEmpty && headerValue.isNotEmpty) {
        headers[key] = headerValue;
      }
    }
    return headers.isEmpty ? null : headers;
  }

  Map<String, dynamic>? _asMap(Object? value) {
    if (value is! Map) return null;
    return value.map((key, value) => MapEntry(key.toString(), value));
  }

  Map<String, String>? _asStringMap(Object? value) {
    final map = _asMap(value);
    if (map == null || map.isEmpty) return null;
    return map.map((key, value) => MapEntry(key, value.toString()));
  }

  List<String> _stringList(Object? value) {
    if (value is List) {
      return value
          .map((item) => item.toString())
          .where((item) => item.isNotEmpty)
          .toList();
    }
    if (value is String) {
      return value
          .split(',')
          .map((item) => item.trim())
          .where((item) => item.isNotEmpty)
          .toList();
    }
    return [];
  }

  bool _truthy(String? value) {
    return _boolValue(value) == true;
  }

  bool? _boolValue(String? value) {
    if (value == null) return null;
    return switch (value.toLowerCase()) {
      '1' || 'true' || 'yes' || 'on' => true,
      '0' || 'false' || 'no' || 'off' => false,
      _ => null,
    };
  }
}

class _ParsedShadowsocks {
  final String credentials;
  final String server;
  final int port;

  const _ParsedShadowsocks({
    required this.credentials,
    required this.server,
    required this.port,
  });
}

extension on String {
  String trimRightChar(String char) {
    var value = this;
    while (value.endsWith(char)) {
      value = value.substring(0, value.length - 1);
    }
    return value;
  }

  String? get takeIfNotEmpty {
    final value = trim();
    return value.isEmpty ? null : value;
  }
}

final subscriptionConverter = SubscriptionConverter();
