declare module "@spacesprotocol/react-native-libveritas" {
  export class Veritas {
    constructor(anchors: any);
    newestAnchor(): number;
    oldestAnchor(): number;
    computeAnchorSetHash(): ArrayBuffer;
    isFinal(commitmentHeight: number): boolean;
    verifyWithOptions(ctx: any, msg: any, options: number): { zones(): any[]; certificates(): any[]; certificate(handle: string): any; message(): any; messageBytes(): ArrayBuffer };
  }
  export class Anchors {
    static fromJson(json: string): any;
    computeAnchorSetHash(): ArrayBuffer;
  }
  export class QueryContext {
    constructor();
    addRequest(handle: string): void;
    addZone(zone: ArrayBuffer): void;
  }
  export class Message {
    constructor(bytes: ArrayBuffer);
    toBytes(): ArrayBuffer;
    update(updates: any[]): void;
  }
  export class MessageBuilder {
    constructor();
    addChain(chainBytes: ArrayBuffer): void;
    addHandle(chainBytes: ArrayBuffer, recordsBytes: ArrayBuffer): void;
    addRecords(handle: string, recordsBytes: ArrayBuffer): void;
    addCert(certBytes: ArrayBuffer): void;
    addUpdate(entry: any): void;
    chainProofRequest(): any;
    build(chainProof: ArrayBuffer): Message;
  }
  export class RecordSet {
    constructor(data: ArrayBuffer);
    static pack(records: any[]): RecordSet;
    toBytes(): ArrayBuffer;
    signingId(): ArrayBuffer;
    unpack(): any[];
  }
  export class VerifiedMessage {
    zones(): any[];
    certificates(): any[];
    certificate(handle: string): any;
    message(): Message;
    messageBytes(): ArrayBuffer;
  }
  export class Zone {
    handle: string;
  }
  export class Lookup {
    constructor(names: string[]);
    start(): string[];
    advance(zones: any[]): string[];
    expandZones(zones: any[]): any[];
  }
  export function zoneToBytes(zone: any): ArrayBuffer;
  export function zoneToJson(zone: any): string;
  export function decodeZone(bytes: ArrayBuffer): any;
  export function decodeCertificate(bytes: ArrayBuffer): string;
  export function createOffchainRecords(recordSet: RecordSet, signature: ArrayBuffer): ArrayBuffer;
  export function zoneIsBetterThan(a: any, b: any): boolean;
  export function hashSignableMessage(msg: ArrayBuffer): ArrayBuffer;
  export function verifySchnorr(msgHash: ArrayBuffer, signature: ArrayBuffer, pubkey: ArrayBuffer): void;
  export function verifySpacesMessage(msg: ArrayBuffer, signature: ArrayBuffer, pubkey: ArrayBuffer): void;
  export function createCertificateChain(subject: string, certBytesList: ArrayBuffer[]): ArrayBuffer;
}
