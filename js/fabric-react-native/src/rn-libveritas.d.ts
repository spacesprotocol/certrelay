declare module "@spacesprotocol/react-native-libveritas" {
  export class Veritas {
    constructor(anchors: any, devMode: boolean);
    newestAnchor(): number;
    verifyMessage(ctx: any, msg: ArrayBuffer): { zones(): any[] };
  }
  export class VeritasAnchors {
    static fromJson(json: string): any;
  }
  export class VeritasQueryContext {
    constructor();
    addRequest(handle: string): void;
    addZone(zone: ArrayBuffer): void;
  }
}
