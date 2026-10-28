'use strict';

/*
 * Firewall policy engine for Node.js.
 *
 * The implementation separates:
 *   1. stateless rule matching,
 *   2. stateful connection tracking,
 *   3. zone classification,
 *   4. policy evaluation,
 *   5. asynchronous event logging.
 *
 * No third-party packages are required.
 */

const { EventEmitter } = require('node:events');
const net = require('node:net');

const Action = Object.freeze({
  ALLOW: 'ALLOW',
  DENY: 'DENY'
});

const Protocol = Object.freeze({
  TCP: 'TCP',
  UDP: 'UDP',
  ICMP: 'ICMP'
});

const Direction = Object.freeze({
  INBOUND: 'INBOUND',
  OUTBOUND: 'OUTBOUND'
});

class FirewallError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FirewallError';
  }
}

function assertIPv4(address) {
  if (!net.isIPv4(address)) {
    throw new FirewallError(`Invalid IPv4 address: ${address}`);
  }
}

function ipToInteger(address) {
  assertIPv4(address);

  return address
    .split('.')
    .reduce((value, octet) => ((value << 8) | Number(octet)) >>> 0, 0);
}

function networkRange(cidr) {
  const [address, prefixText] = cidr.split('/');
  assertIPv4(address);

  const prefix = Number(prefixText);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new FirewallError(`Invalid CIDR prefix: ${cidr}`);
  }

  const value = ipToInteger(address);
  const mask = prefix === 0
    ? 0
    : (0xffffffff << (32 - prefix)) >>> 0;

  return {
    network: value & mask,
    mask
  };
}

function inNetwork(address, cidr) {
  const range = networkRange(cidr);
  return (ipToInteger(address) & range.mask) === range.network;
}

function validatePort(port, fieldName) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new FirewallError(`Invalid ${fieldName}: ${port}`);
  }
}

function validatePacket(packet) {
  assertIPv4(packet.srcIp);
  assertIPv4(packet.dstIp);

  if (!Object.values(Protocol).includes(packet.protocol)) {
    throw new FirewallError(`Unsupported protocol: ${packet.protocol}`);
  }

  if (!Object.values(Direction).includes(packet.direction)) {
    throw new FirewallError(`Unsupported direction: ${packet.direction}`);
  }

  if (packet.protocol === Protocol.TCP || packet.protocol === Protocol.UDP) {
    validatePort(packet.srcPort, 'source port');
    validatePort(packet.dstPort, 'destination port');
  } else if (packet.srcPort !== undefined || packet.dstPort !== undefined) {
    throw new FirewallError('ICMP cannot contain TCP/UDP ports');
  }
}

class FirewallRule {
  constructor({
    name,
    action,
    protocol = null,
    sourceCidr = null,
    destinationCidr = null,
    sourcePort = null,
    destinationPort = null,
    direction = null,
    interfaceName = null
  }) {
    if (!name || !Object.values(Action).includes(action)) {
      throw new FirewallError('A rule requires a name and valid action');
    }

    this.name = name;
    this.action = action;
    this.protocol = protocol;
    this.sourceCidr = sourceCidr;
    this.destinationCidr = destinationCidr;
    this.sourcePort = sourcePort;
    this.destinationPort = destinationPort;
    this.direction = direction;
    this.interfaceName = interfaceName;

    if (sourceCidr) networkRange(sourceCidr);
    if (destinationCidr) networkRange(destinationCidr);
    if (sourcePort !== null) validatePort(sourcePort, 'source rule port');
    if (destinationPort !== null) validatePort(destinationPort, 'destination rule port');
  }

  matches(packet) {
    if (this.protocol !== null && this.protocol !== packet.protocol) return false;

    if (this.sourceCidr && !inNetwork(packet.srcIp, this.sourceCidr)) {
      return false;
    }

    if (this.destinationCidr && !inNetwork(packet.dstIp, this.destinationCidr)) {
      return false;
    }

    if (this.sourcePort !== null && this.sourcePort !== packet.srcPort) {
      return false;
    }

    if (this.destinationPort !== null && this.destinationPort !== packet.dstPort) {
      return false;
    }

    if (this.direction !== null && this.direction !== packet.direction) {
      return false;
    }

    if (
      this.interfaceName !== null &&
      this.interfaceName !== packet.interfaceName
    ) {
      return false;
    }

    return true;
  }
}

function flowKey(packet) {
  return [
    packet.srcIp,
    packet.dstIp,
    packet.protocol,
    packet.srcPort ?? '-',
    packet.dstPort ?? '-'
  ].join('|');
}

function reverseFlowKey(packet) {
  return [
    packet.dstIp,
    packet.srcIp,
    packet.protocol,
    packet.dstPort ?? '-',
    packet.srcPort ?? '-'
  ].join('|');
}

class Firewall extends EventEmitter {
  constructor(rules, {
    defaultAction = Action.DENY,
    stateful = false,
    maxTrackedFlows = 10000
  } = {}) {
    super();

    if (!Array.isArray(rules)) {
      throw new FirewallError('Rules must be an array');
    }

    if (!Object.values(Action).includes(defaultAction)) {
      throw new FirewallError('Invalid default action');
    }

    this.rules = [...rules];
    this.defaultAction = defaultAction;
    this.stateful = stateful;
    this.maxTrackedFlows = maxTrackedFlows;
    this.establishedFlows = new Map();
  }

  evaluate(packet) {
    validatePacket(packet);

    const key = flowKey(packet);
    const reverseKey = reverseFlowKey(packet);

    if (
      this.stateful &&
      (this.establishedFlows.has(key) || this.establishedFlows.has(reverseKey))
    ) {
      const result = {
        action: Action.ALLOW,
        rule: 'STATEFUL-ESTABLISHED',
        reason: 'Existing connection state permits the packet'
      };

      this.emit('decision', { packet, result });
      return result;
    }

    const matchedRule = this.rules.find(rule => rule.matches(packet));

    const result = matchedRule
      ? {
          action: matchedRule.action,
          rule: matchedRule.name,
          reason: 'First matching rule'
        }
      : {
          action: this.defaultAction,
          rule: 'DEFAULT',
          reason: 'No rule matched'
        };

    if (
      this.stateful &&
      result.action === Action.ALLOW &&
      this.establishedFlows.size < this.maxTrackedFlows
    ) {
      this.establishedFlows.set(key, Date.now());
    }

    this.emit('decision', { packet, result });
    return result;
  }

  expireOlderThan(maxAgeMs) {
    const cutoff = Date.now() - maxAgeMs;

    for (const [key, timestamp] of this.establishedFlows) {
      if (timestamp < cutoff) {
        this.establishedFlows.delete(key);
      }
    }
  }
}

class ZonePolicy {
  constructor({
    sourceZone,
    destinationZone,
    action,
    protocol = null,
    destinationPort = null
  }) {
    this.sourceZone = sourceZone;
    this.destinationZone = destinationZone;
    this.action = action;
    this.protocol = protocol;
    this.destinationPort = destinationPort;
  }

  matches(sourceZone, destinationZone, packet) {
    return (
      this.sourceZone === sourceZone &&
      this.destinationZone === destinationZone &&
      (this.protocol === null || this.protocol === packet.protocol) &&
      (
        this.destinationPort === null ||
        this.destinationPort === packet.dstPort
      )
    );
  }
}

class ZoneFirewall extends EventEmitter {
  constructor(zones, policies) {
    super();
    this.zones = new Map(zones.map(zone => [zone.name, zone]));
    this.policies = [...policies];
    this.state = new Set();
  }

  classify(ip) {
    const matches = [];

    for (const zone of this.zones.values()) {
      if (zone.networks.some(cidr => inNetwork(ip, cidr))) {
        matches.push(zone.name);
      }
    }

    if (matches.length === 0) return 'UNTRUSTED';

    if (matches.length > 1) {
      throw new FirewallError(
        `Ambiguous zone assignment for ${ip}: ${matches.join(', ')}`
      );
    }

    return matches[0];
  }

  evaluate(packet) {
    validatePacket(packet);

    const sourceZone = this.classify(packet.srcIp);
    const destinationZone = this.classify(packet.dstIp);
    const key = flowKey(packet);
    const reverse = reverseFlowKey(packet);

    if (this.state.has(key) || this.state.has(reverse)) {
      return this.emitDecision(packet, {
        action: Action.ALLOW,
        rule: 'ZONE-ESTABLISHED',
        sourceZone,
        destinationZone
      });
    }

    const policy = this.policies.find(item =>
      item.matches(sourceZone, destinationZone, packet)
    );

    const result = policy
      ? {
          action: policy.action,
          rule: `${sourceZone}->${destinationZone}`,
          sourceZone,
          destinationZone
        }
      : {
          action: Action.DENY,
          rule: 'ZONE-DEFAULT-DENY',
          sourceZone,
          destinationZone
        };

    if (result.action === Action.ALLOW) {
      this.state.add(key);
    }

    return this.emitDecision(packet, result);
  }

  emitDecision(packet, result) {
    this.emit('decision', { packet, result });
    return result;
  }
}

function makePacket(overrides) {
  return {
    srcIp: '203.0.113.10',
    dstIp: '10.0.10.20',
    protocol: Protocol.TCP,
    srcPort: 45000,
    dstPort: 443,
    direction: Direction.INBOUND,
    interfaceName: 'external',
    ...overrides
  };
}

async function auditDecision(firewall, packet) {
  return new Promise(resolve => {
    setImmediate(() => {
      resolve(firewall.evaluate(packet));
    });
  });
}

async function main() {
  const rules = [
    new FirewallRule({
      name: 'ALLOW-HTTPS-INBOUND',
      action: Action.ALLOW,
      protocol: Protocol.TCP,
      destinationCidr: '10.0.10.0/24',
      destinationPort: 443,
      direction: Direction.INBOUND,
      interfaceName: 'external'
    }),
    new FirewallRule({
      name: 'ALLOW-DNS-OUTBOUND',
      action: Action.ALLOW,
      protocol: Protocol.UDP,
      sourceCidr: '10.0.20.0/24',
      destinationPort: 53,
      direction: Direction.OUTBOUND
    }),
    new FirewallRule({
      name: 'DENY-TELNET',
      action: Action.DENY,
      protocol: Protocol.TCP,
      destinationPort: 23
    })
  ];

  const firewall = new Firewall(rules, {
    defaultAction: Action.DENY,
    stateful: true
  });

  firewall.on('decision', ({ packet, result }) => {
    console.log(
      `${packet.srcIp}:${packet.srcPort ?? '-'} -> ` +
      `${packet.dstIp}:${packet.dstPort ?? '-'} ` +
      `${result.action} [${result.rule}]`
    );
  });

  const packets = [
    makePacket({}),
    makePacket({
      srcIp: '198.51.100.20',
      dstIp: '10.0.10.20',
      srcPort: 443,
      dstPort: 45000,
      direction: Direction.INBOUND
    }),
    makePacket({
      dstPort: 22
    }),
    makePacket({
      srcIp: '10.0.20.10',
      dstIp: '8.8.8.8',
      protocol: Protocol.UDP,
      srcPort: 51000,
      dstPort: 53,
      direction: Direction.OUTBOUND,
      interfaceName: 'internal'
    })
  ];

  console.log('STATEFUL PACKET EVALUATION');
  for (const packet of packets) {
    await auditDecision(firewall, packet);
  }

  const zones = [
    {
      name: 'DMZ',
      networks: ['10.0.10.0/24']
    },
    {
      name: 'INTERNAL',
      networks: ['10.0.20.0/24']
    },
    {
      name: 'INTERNET',
      networks: ['0.0.0.0/1', '128.0.0.0/1']
    }
  ];

  const policies = [
    new ZonePolicy({
      sourceZone: 'INTERNET',
      destinationZone: 'DMZ',
      action: Action.ALLOW,
      protocol: Protocol.TCP,
      destinationPort: 443
    }),
    new ZonePolicy({
      sourceZone: 'INTERNAL',
      destinationZone: 'INTERNET',
      action: Action.ALLOW,
      protocol: Protocol.TCP,
      destinationPort: 443
    }),
    new ZonePolicy({
      sourceZone: 'INTERNAL',
      destinationZone: 'INTERNET',
      action: Action.ALLOW,
      protocol: Protocol.UDP,
      destinationPort: 53
    })
  ];

  const zoneFirewall = new ZoneFirewall(zones, policies);

  zoneFirewall.on('decision', ({ result }) => {
    console.log(
      `ZONE ${result.sourceZone}->${result.destinationZone}: ` +
      `${result.action} [${result.rule}]`
    );
  });

  console.log('\nZONE POLICY EVALUATION');

  zoneFirewall.evaluate(makePacket({}));
  zoneFirewall.evaluate(makePacket({
    srcIp: '10.0.20.10',
    dstIp: '198.51.100.20',
    srcPort: 51000,
    dstPort: 443,
    direction: Direction.OUTBOUND,
    interfaceName: 'internal'
  }));
  zoneFirewall.evaluate(makePacket({
    srcIp: '198.51.100.20',
    dstIp: '10.0.20.10',
    srcPort: 51001,
    dstPort: 22,
    direction: Direction.INBOUND
  }));

  const unmatched = firewall.evaluate(makePacket({
    dstPort: 22
  }));

  if (unmatched.action !== Action.DENY) {
    throw new FirewallError('Default-deny invariant failed');
  }

  console.log('\nVALIDATION: default-deny invariant passed.');
}

main().catch(error => {
  console.error(`Firewall execution failed: ${error.message}`);
  process.exitCode = 1;
});
