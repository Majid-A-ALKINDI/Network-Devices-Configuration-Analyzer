/**
 * Network Devices Configuration Analyzer — Parser
 * Supports Cisco IOS, IOS-XE, NX-OS style configs for core switches and routers
 */

const ConfigParser = (() => {

  function parseAll(text, deviceName) {
    return {
      deviceName: deviceName || detectHostname(text) || 'Unknown Device',
      deviceType: detectDeviceType(text),
      versionInfo: parseVersionInfo(text),
      vlans: parseVlans(text),
      interfaces: parseInterfaces(text),
      routes: parseStaticRoutes(text),
      ospf: parseOspf(text),
      ospfVrf: parseOspfVrf(text),
      bgp: parseBgp(text),
      bgpVrfAF: parseBgpVrfAF(text),
      vrfs: parseVrfs(text),
      acls: parseAcls(text),
      trunkLinks: parseTrunkLinks(text),
      credentials: parseCredentials(text),
    };
  }

  function detectHostname(text) {
    const m = text.match(/^hostname\s+(\S+)/m);
    return m ? m[1] : null;
  }

  function detectDeviceType(text) {
    if (/^version\s+\d/m.test(text) && /interface\s+Vlan/i.test(text)) return 'Core Switch (IOS)';
    if (/^version\s+\d/m.test(text) && /interface\s+GigabitEthernet/i.test(text)) return 'Router (IOS)';
    if (/^feature\s+/m.test(text) || /^vlan\s+\d/m.test(text)) return 'Core Switch (NX-OS)';
    if (/interface\s+Ethernet/i.test(text)) return 'Switch';
    return 'Network Device';
  }

  // ── Version collector ────────────────────────────────────────────────────
  function parseVersionInfo(text) {
    const lines = text.split(/\r?\n/);

    const data = {
      osVersion: '',
      softwareHint: '',
      platformHint: '',
      sampleRevision: '',
      evidence: [],
    };

    function pushEvidence(type, value, lineNo, lineText) {
      if (!value) return;
      data.evidence.push({ type, value, line: lineNo, configLine: lineText || '' });
    }

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] || '';
      const line = raw.trim();

      let m = line.match(/^version\s+(.+)$/i);
      if (m) {
        const v = m[1].trim();
        if (!data.osVersion) data.osVersion = v;
        pushEvidence('version-command', v, i + 1, raw);
      }

      m = line.match(/^!\s*Sample\s+Revision\s*:\s*(.+)$/i);
      if (m) {
        const v = m[1].trim();
        if (!data.sampleRevision) data.sampleRevision = v;
        pushEvidence('sample-revision', v, i + 1, raw);
      }

      m = line.match(/^!\s*Cisco\s+(.+)$/i);
      if (m) {
        const v = m[1].trim();
        if (!data.softwareHint) data.softwareHint = v;
        pushEvidence('comment-software', v, i + 1, raw);
      }

      m = line.match(/^boot\s+system\s+\S*\s*(.+)$/i);
      if (m) {
        pushEvidence('boot-image', m[1].trim(), i + 1, raw);
      }

      m = line.match(/^version\s+([\d.]+)\s*$/i);
      if (m && !data.platformHint) {
        // Keep this neutral: platform may be detected from comments in sample configs.
        data.platformHint = /nx-os/i.test(text) ? 'NX-OS' : 'IOS/IOS-XE';
      }
    }

    if (!data.softwareHint) {
      const c = text.match(/Cisco\s+([A-Za-z0-9_.\-/ ]+)/i);
      if (c) data.softwareHint = c[1].trim();
    }

    return data;
  }

  // ── VLAN parsing ──────────────────────────────────────────────────────────
  function parseVlans(text) {
    const vlans = {};

    // IOS: "vlan 10\n name MGMT"
    const vlanBlocks = text.matchAll(/^vlan\s+(\d+(?:,\d+|-\d+)*)\s*\n((?:[ \t]+.*\n)*)/gm);
    for (const block of vlanBlocks) {
      const ids = expandVlanRange(block[1]);
      const nameMatch = block[2].match(/name\s+(\S+)/i);
      const name = nameMatch ? nameMatch[1] : '';
      ids.forEach(id => {
        if (!vlans[id]) vlans[id] = { id, name, interfaces: [], networks: [] };
        else if (name) vlans[id].name = name;
      });
    }

    // Collect SVI networks: "interface VlanXX\n ip address x.x.x.x y.y.y.y"
    const sviBlocks = text.matchAll(/interface\s+[Vv]lan(\d+)([\s\S]*?)(?=\ninterface|\nend|\n![\s]*\n(?=\S))/g);
    for (const block of sviBlocks) {
      const id = parseInt(block[1]);
      if (!vlans[id]) vlans[id] = { id, name: '', interfaces: [], networks: [] };
      const ipMatch = block[2].match(/ip\s+address\s+([\d.]+)\s+([\d.]+)/i);
      if (ipMatch) {
        const cidr = maskToCidr(ipMatch[2]);
        const network = networkAddress(ipMatch[1], ipMatch[2]);
        vlans[id].networks.push({ ip: ipMatch[1], mask: ipMatch[2], cidr, network: `${network}/${cidr}` });
      }
      const descMatch = block[2].match(/description\s+(.+)/i);
      if (descMatch && !vlans[id].name) vlans[id].name = descMatch[1].trim();
    }

    // Switchport access/trunk vlan assignment
    const ifBlocks = [...text.matchAll(/interface\s+(\S+)([\s\S]*?)(?=\ninterface|\nend|\n![\s]*\n(?=\S))/g)];
    for (const block of ifBlocks) {
      const ifName = block[1];
      const body = block[2];
      const accessMatch = body.match(/switchport\s+access\s+vlan\s+(\d+)/i);
      if (accessMatch) {
        const id = parseInt(accessMatch[1]);
        if (!vlans[id]) vlans[id] = { id, name: '', interfaces: [], networks: [] };
        if (!vlans[id].interfaces.includes(ifName)) vlans[id].interfaces.push(ifName);
      }
      const trunkMatch = body.match(/switchport\s+trunk\s+allowed\s+vlan\s+([\d,add\s-]+)/i);
      if (trunkMatch) {
        expandVlanRange(trunkMatch[1].replace(/add\s*/gi, '')).forEach(id => {
          if (!vlans[id]) vlans[id] = { id, name: '', interfaces: [], networks: [] };
          if (!vlans[id].interfaces.includes(ifName)) vlans[id].interfaces.push(ifName);
        });
      }
    }

    return Object.values(vlans).sort((a, b) => a.id - b.id);
  }

  // ── Interface parsing ─────────────────────────────────────────────────────
  function parseInterfaces(text) {
    const interfaces = [];
    const ifBlocks = [...text.matchAll(/interface\s+(\S+)([\s\S]*?)(?=\ninterface|\nend$|\n![\s]*\n(?=\S))/gm)];
    for (const block of ifBlocks) {
      const name = block[1];
      const body = block[2];
      const iface = { name, description: '', ip: null, mask: null, cidr: null, network: null, vlan: null, dot1qVlan: null, mode: null, shutdown: false, vrfName: null };

      const descMatch = body.match(/description\s+(.+)/i);
      if (descMatch) iface.description = descMatch[1].trim();

      const ipMatch = body.match(/ip\s+address\s+([\d.]+)\s+([\d.]+)/i);
      if (ipMatch) {
        iface.ip = ipMatch[1];
        iface.mask = ipMatch[2];
        iface.cidr = maskToCidr(ipMatch[2]);
        iface.network = `${networkAddress(ipMatch[1], ipMatch[2])}/${iface.cidr}`;
      }

      // IP address with prefix (NX-OS style)
      const ipCidrMatch = body.match(/ip\s+address\s+([\d.]+)\/([\d]+)/i);
      if (ipCidrMatch && !iface.ip) {
        iface.ip = ipCidrMatch[1];
        iface.cidr = parseInt(ipCidrMatch[2]);
        iface.mask = cidrToMask(iface.cidr);
        iface.network = `${networkAddress(iface.ip, iface.mask)}/${iface.cidr}`;
      }

      const modeMatch = body.match(/switchport\s+mode\s+(\S+)/i);
      if (modeMatch) iface.mode = modeMatch[1];

      const accessVlan = body.match(/switchport\s+access\s+vlan\s+(\d+)/i);
      if (accessVlan) iface.vlan = parseInt(accessVlan[1]);

      const vlanMatch = name.match(/[Vv]lan(\d+)/);
      if (vlanMatch) iface.vlan = parseInt(vlanMatch[1]);

      if (/^\s*shutdown\s*$/m.test(body)) iface.shutdown = true;

      const vrfMatch = body.match(/vrf\s+(?:forwarding|member)\s+(\S+)/i);
      if (vrfMatch) iface.vrfName = vrfMatch[1];

      const dot1qMatch = body.match(/encapsulation\s+dot1[Qq]\s+(\d+)/i);
      if (dot1qMatch) iface.dot1qVlan = parseInt(dot1qMatch[1]);

      const aclInMatch  = body.match(/ip\s+access-group\s+(\S+)\s+in/i);
      const aclOutMatch = body.match(/ip\s+access-group\s+(\S+)\s+out/i);
      iface.aclIn  = aclInMatch  ? aclInMatch[1]  : null;
      iface.aclOut = aclOutMatch ? aclOutMatch[1] : null;

      interfaces.push(iface);
    }
    return interfaces;
  }

  // ── Static Routes ─────────────────────────────────────────────────────────
  function parseStaticRoutes(text) {
    const routes = [];
    const routeRe = /ip\s+route\s+(?:vrf\s+(\S+)\s+)?([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s+\d+)?(?:\s+name\s+(.+))?/gm;
    for (const m of text.matchAll(routeRe)) {
      routes.push({
        vrf: m[1] || 'global',
        network: m[2],
        mask: m[3],
        cidr: maskToCidr(m[3]),
        nexthop: m[4],
        name: m[5] ? m[5].trim() : '',
      });
    }
    // prefix notation
    const prefixRe = /ip\s+route\s+(?:vrf\s+(\S+)\s+)?([\d.]+)\/([\d]+)\s+([\d.]+)/gm;
    for (const m of text.matchAll(prefixRe)) {
      routes.push({
        vrf: m[1] || 'global',
        network: m[2],
        mask: cidrToMask(parseInt(m[3])),
        cidr: parseInt(m[3]),
        nexthop: m[4],
        name: '',
      });
    }
    return routes;
  }

  // ── OSPF ──────────────────────────────────────────────────────────────────
  function parseOspf(text) {
    const ospfProcesses = [];
    const ospfBlocks = [...text.matchAll(/router\s+ospf\s+(\d+)([\s\S]*?)(?=\nrouter\s|\nend$|\n![\s]*\n(?=\S))/gm)];
    for (const block of ospfBlocks) {
      const pid = block[1];
      const body = block[2];
      const networks = [];
      for (const n of body.matchAll(/network\s+([\d.]+)\s+([\d.]+)\s+area\s+([\d.]+)/g)) {
        networks.push({ network: n[1], wildcard: n[2], area: n[3] });
      }
      const routerId = (body.match(/router-id\s+([\d.]+)/) || [])[1] || null;
      ospfProcesses.push({ pid, routerId, networks });
    }
    return ospfProcesses;
  }

  // ── BGP ───────────────────────────────────────────────────────────────────
  function parseBgp(text) {
    const bgpBlocks = [...text.matchAll(/router\s+bgp\s+(\d+)([\s\S]*?)(?=\nrouter\s|\nend$|\n![\s]*\n(?=\S))/gm)];
    if (!bgpBlocks.length) return null;
    const block = bgpBlocks[0];
    const asn = block[1];
    const body = block[2];
    const neighbors = [];
    for (const n of body.matchAll(/neighbor\s+([\d.]+)\s+remote-as\s+(\d+)/g)) {
      const descMatch = body.match(new RegExp(`neighbor\\s+${n[1]}\\s+description\\s+(.+)`));
      neighbors.push({ ip: n[1], remoteAs: n[2], description: descMatch ? descMatch[1].trim() : '' });
    }
    const networks = [];
    for (const n of body.matchAll(/network\s+([\d.]+)(?:\s+mask\s+([\d.]+))?/g)) {
      networks.push({ network: n[1], mask: n[2] || '255.255.255.255' });
    }
    return { asn, neighbors, networks };
  }

  // ── VRF ───────────────────────────────────────────────────────────────────
  function parseVrfs(text) {
    const vrfs = {};
    // IOS: "ip vrf NAME" or "vrf definition NAME"
    for (const m of text.matchAll(/(?:ip\s+vrf|vrf\s+definition)\s+(\S+)((?:\n[ \t]+[^\n]+)*)/gm)) {
      const name = m[1];
      const body = m[2];
      const rdMatch = body.match(/rd\s+(\S+)/);
      const descMatch = body.match(/description\s+(.+)/);
      const rtImport = [...body.matchAll(/route-target\s+(?:import|both)\s+(\S+)/gi)].map(r => r[1]);
      const rtExport = [...body.matchAll(/route-target\s+(?:export|both)\s+(\S+)/gi)].map(r => r[1]);
      vrfs[name] = {
        name,
        rd: rdMatch ? rdMatch[1] : '',
        description: descMatch ? descMatch[1].trim() : '',
        rtImport,
        rtExport,
      };
    }
    // NX-OS style: "vrf context NAME"
    for (const m of text.matchAll(/vrf\s+context\s+(\S+)((?:\n[ \t]+[^\n]+)*)/gm)) {
      const name = m[1];
      if (name === 'management') continue;
      const body = m[2];
      const rdMatch = body.match(/rd\s+(\S+)/);
      const descMatch = body.match(/description\s+(.+)/);
      const rtImport = [...body.matchAll(/route-target\s+(?:import|both)\s+(\S+)/gi)].map(r => r[1]);
      const rtExport = [...body.matchAll(/route-target\s+(?:export|both)\s+(\S+)/gi)].map(r => r[1]);
      if (!vrfs[name]) vrfs[name] = { name, rd: '', description: '', rtImport: [], rtExport: [] };
      if (rdMatch) vrfs[name].rd = rdMatch[1];
      if (descMatch) vrfs[name].description = descMatch[1].trim();
      vrfs[name].rtImport.push(...rtImport);
      vrfs[name].rtExport.push(...rtExport);
    }
    return Object.values(vrfs);
  }

  // ── Per-VRF OSPF ──────────────────────────────────────────────────────────
  function parseOspfVrf(text) {
    const result = [];
    // "router ospf X vrf VRFNAME" (IOS-XE)
    for (const block of text.matchAll(/router\s+ospf\s+(\d+)\s+vrf\s+(\S+)([\s\S]*?)(?=\nrouter\s|\nend$|\n![\s]*\n(?=\S))/gm)) {
      const pid = block[1], vrfName = block[2], body = block[3];
      const nets = [...body.matchAll(/network\s+([\d.]+)\s+([\d.]+)\s+area\s+([\d.]+)/g)]
        .map(n => ({ network: n[1], wildcard: n[2], area: n[3] }));
      const routerId = (body.match(/router-id\s+([\d.]+)/) || [])[1] || null;
      result.push({ pid, vrfName, routerId, networks: nets });
    }
    return result;
  }

  // ── Per-VRF BGP address-family ────────────────────────────────────────────
  function parseBgpVrfAF(text) {
    const result = [];
    const bgpBlock = text.match(/router\s+bgp\s+(\d+)([\s\S]*?)(?=\nend$|\Z)/m);
    if (!bgpBlock) return result;
    const asn = bgpBlock[1];
    // "address-family ipv4 vrf VRFNAME"
    for (const af of bgpBlock[2].matchAll(/address-family\s+\S+\s+vrf\s+(\S+)([\s\S]*?)(?=\s+exit-address-family|\s+address-family|$)/gm)) {
      const vrfName = af[1], body = af[2];
      const neighbors = [...body.matchAll(/neighbor\s+([\d.]+)\s+remote-as\s+(\d+)/g)]
        .map(n => ({ ip: n[1], remoteAs: n[2] }));
      const networks = [...body.matchAll(/network\s+([\d.]+)(?:\s+mask\s+([\d.]+))?/g)]
        .map(n => ({ network: n[1], mask: n[2] || '255.255.255.255' }));
      result.push({ asn, vrfName, neighbors, networks });
    }
    return result;
  }

  // ── ACL parsing ───────────────────────────────────────────────────────────
  function parseAcls(text) {
    const acls = {};
    // Named extended/standard: "ip access-list extended|standard NAME"
    for (const m of text.matchAll(/ip\s+access-list\s+(?:extended|standard)\s+(\S+)((?:\n[ \t]+[^\n]+)*)/gm)) {
      const name = m[1];
      const entries = [];
      for (const line of m[2].matchAll(/(?:permit|deny)\s+(.+)/gi)) {
        entries.push(line[0].trim());
      }
      acls[name] = { name, entries };
    }
    // Numbered ACLs: "access-list 10 permit ..."
    for (const m of text.matchAll(/^access-list\s+(\d+)\s+(permit|deny)\s+(.+)/gm)) {
      const name = m[1];
      if (!acls[name]) acls[name] = { name, entries: [] };
      acls[name].entries.push(`${m[2]} ${m[3].trim()}`);
    }
    return acls;
  }

  // ── Trunk link parsing ────────────────────────────────────────────────────
  function parseTrunkLinks(text) {
    const trunks = [];
    const ifBlocks = [...text.matchAll(/interface\s+(\S+)([\s\S]*?)(?=\ninterface|\nend$|\n![\s]*\n(?=\S))/gm)];
    for (const block of ifBlocks) {
      const name = block[1];
      const body = block[2];
      if (!/switchport\s+mode\s+trunk/i.test(body)) continue;
      const allowedMatch = body.match(/switchport\s+trunk\s+allowed\s+vlan\s+([\d,add\s-]+)/i);
      const nativeMatch  = body.match(/switchport\s+trunk\s+native\s+vlan\s+(\d+)/i);
      const descMatch    = body.match(/description\s+(.+)/i);
      const allowedVlans = allowedMatch
        ? expandVlanRange(allowedMatch[1].replace(/add\s*/gi, ''))
        : [];
      trunks.push({
        name,
        description: descMatch ? descMatch[1].trim() : '',
        allowedVlans,
        nativeVlan: nativeMatch ? parseInt(nativeMatch[1]) : 1,
      });
    }
    return trunks;
  }

  // ── Credentials parsing ───────────────────────────────────────────────────
  function parseCredentials(text) {
    const lines = text.split(/\r?\n/);
    const users = [];
    const enable = [];
    const linePasswords = [];

    function classifyEncoding(typeNum, keyword) {
      const type = String(typeNum || '').trim();
      if (!type) return { encType: keyword === 'secret' ? 'secret-unspecified' : 'plaintext', reversible: keyword !== 'secret' };
      if (type === '0') return { encType: 'plaintext', reversible: true };
      if (type === '7') return { encType: 'cisco-type7', reversible: true };
      if (type === '5') return { encType: 'md5-type5', reversible: false };
      if (type === '8') return { encType: 'pbkdf2-type8', reversible: false };
      if (type === '9') return { encType: 'scrypt-type9', reversible: false };
      if (type === '6') return { encType: 'aes-type6', reversible: false };
      return { encType: `type-${type}`, reversible: false };
    }

    // username lines
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!/^username\s+/i.test(line)) continue;

      // username bob privilege 15 secret 9 <hash>
      let m = line.match(/^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+(password|secret)\s+([0-9])\s+(.+)$/i);
      if (m) {
        const username = m[1];
        const privilege = m[2] || '';
        const keyword = m[3].toLowerCase();
        const typeNum = m[4];
        const value = m[5].trim();
        const info = classifyEncoding(typeNum, keyword);
        const decoded = info.encType === 'cisco-type7' ? ciscoType7Decode(value) : (info.encType === 'plaintext' ? value : '');
        users.push({
          username,
          privilege,
          keyword,
          encodingType: info.encType,
          reversible: info.reversible,
          value,
          decoded: decoded || '',
          line: i + 1,
          configLine: lines[i],
        });
        continue;
      }

      // username bob password plainText (type omitted)
      m = line.match(/^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+(password|secret)\s+(.+)$/i);
      if (m) {
        const username = m[1];
        const privilege = m[2] || '';
        const keyword = m[3].toLowerCase();
        const value = m[4].trim();
        const info = keyword === 'secret'
          ? { encType: 'secret-unspecified', reversible: false }
          : { encType: 'plaintext', reversible: true };
        users.push({
          username,
          privilege,
          keyword,
          encodingType: info.encType,
          reversible: info.reversible,
          value,
          decoded: info.encType === 'plaintext' ? value : '',
          line: i + 1,
          configLine: lines[i],
        });
      }
    }

    // enable password/secret
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      let m = line.match(/^enable\s+(password|secret)\s+([0-9])\s+(.+)$/i);
      if (m) {
        const keyword = m[1].toLowerCase();
        const typeNum = m[2];
        const value = m[3].trim();
        const info = classifyEncoding(typeNum, keyword);
        const decoded = info.encType === 'cisco-type7' ? ciscoType7Decode(value) : (info.encType === 'plaintext' ? value : '');
        enable.push({
          keyword,
          encodingType: info.encType,
          reversible: info.reversible,
          value,
          decoded: decoded || '',
          line: i + 1,
          configLine: lines[i],
        });
        continue;
      }

      m = line.match(/^enable\s+(password|secret)\s+(.+)$/i);
      if (m) {
        const keyword = m[1].toLowerCase();
        const value = m[2].trim();
        const info = keyword === 'secret'
          ? { encType: 'secret-unspecified', reversible: false }
          : { encType: 'plaintext', reversible: true };
        enable.push({
          keyword,
          encodingType: info.encType,
          reversible: info.reversible,
          value,
          decoded: info.encType === 'plaintext' ? value : '',
          line: i + 1,
          configLine: lines[i],
        });
      }
    }

    // line console/vty password
    const lineBlocks = [...text.matchAll(/^line\s+([^\n]+)\n([\s\S]*?)(?=^line\s+|^end$|^!\s*$|\Z)/gm)];
    for (const b of lineBlocks) {
      const lineName = `line ${b[1].trim()}`;
      const body = b[2] || '';
      const absoluteStart = text.slice(0, b.index).split(/\r?\n/).length;
      const bodyLines = body.split(/\r?\n/);
      bodyLines.forEach((raw, idx) => {
        const t = raw.trim();
        let m = t.match(/^password\s+([0-9])\s+(.+)$/i);
        if (m) {
          const typeNum = m[1];
          const value = m[2].trim();
          const info = classifyEncoding(typeNum, 'password');
          const decoded = info.encType === 'cisco-type7' ? ciscoType7Decode(value) : (info.encType === 'plaintext' ? value : '');
          linePasswords.push({
            lineName,
            encodingType: info.encType,
            reversible: info.reversible,
            value,
            decoded: decoded || '',
            line: absoluteStart + idx + 1,
            configLine: raw,
          });
          return;
        }
        m = t.match(/^password\s+(.+)$/i);
        if (m) {
          const value = m[1].trim();
          linePasswords.push({
            lineName,
            encodingType: 'plaintext',
            reversible: true,
            value,
            decoded: value,
            line: absoluteStart + idx + 1,
            configLine: raw,
          });
        }
      });
    }

    const hasServicePasswordEncryption = /^service\s+password-encryption\s*$/m.test(text);
    return {
      users,
      enable,
      linePasswords,
      hasServicePasswordEncryption,
    };
  }

  function ciscoType7Decode(enc) {
    try {
      const s = String(enc || '').trim();
      if (!/^[0-9A-Fa-f]+$/.test(s) || s.length < 4 || s.length % 2 !== 0) return '';
      const xlat = 'dsfd;kfoA,.iyewrkldJKDHSUB';
      let seed = parseInt(s.slice(0, 2), 16);
      if (Number.isNaN(seed)) return '';
      let out = '';
      for (let i = 2; i < s.length; i += 2) {
        const b = parseInt(s.slice(i, i + 2), 16);
        if (Number.isNaN(b)) return '';
        out += String.fromCharCode(b ^ xlat.charCodeAt(seed % xlat.length));
        seed++;
      }
      return out;
    } catch (e) {
      return '';
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function expandVlanRange(str) {
    const ids = new Set();
    str.split(',').forEach(part => {
      part = part.trim();
      const range = part.match(/(\d+)-(\d+)/);
      if (range) {
        for (let i = parseInt(range[1]); i <= parseInt(range[2]); i++) ids.add(i);
      } else if (/^\d+$/.test(part)) {
        ids.add(parseInt(part));
      }
    });
    return [...ids];
  }

  function maskToCidr(mask) {
    return mask.split('.').reduce((acc, octet) => acc + parseInt(octet).toString(2).split('1').length - 1, 0);
  }

  function cidrToMask(cidr) {
    const bits = '1'.repeat(cidr) + '0'.repeat(32 - cidr);
    return [0, 8, 16, 24].map(i => parseInt(bits.slice(i, i + 8), 2)).join('.');
  }

  function networkAddress(ip, mask) {
    const ipParts = ip.split('.').map(Number);
    const maskParts = mask.split('.').map(Number);
    return ipParts.map((o, i) => o & maskParts[i]).join('.');
  }

  return { parseAll };
})();
