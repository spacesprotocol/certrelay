declare module "@spacesprotocol/react-native-libveritas" {
  export class Veritas {
    constructor(anchors: any);
    static withDevMode(anchors: any): Veritas;
    newestAnchor(): number;
    verifyMessage(ctx: any, msg: any): { zones(): any[] };
  }
  export class Anchors {
    static fromJson(json: string): any;
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
    constructor(requests: any[]);
    build(chainProof: ArrayBuffer): Message;
    chainProofRequest(): string;
  }
  export class RecordSet {
    constructor(seq: number, recordsJson: string);
    id(): ArrayBuffer;
  }
  export class Zone {
    handle(): string;
    toBytes(): ArrayBuffer;
    toJson(): string;
  }
  export function createOffchainData(recordSet: RecordSet, signature: ArrayBuffer): ArrayBuffer;
}
