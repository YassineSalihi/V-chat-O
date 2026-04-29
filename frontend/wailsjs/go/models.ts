export namespace main {
	
	export class UIMessage {
	    id: string;
	    from: string;
	    fromId: string;
	    content: string;
	    room: string;
	    ts: number;
	    encrypted: boolean;
	    onion: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UIMessage(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.from = source["from"];
	        this.fromId = source["fromId"];
	        this.content = source["content"];
	        this.room = source["room"];
	        this.ts = source["ts"];
	        this.encrypted = source["encrypted"];
	        this.onion = source["onion"];
	    }
	}
	export class UINodeInfo {
	    nodeId: string;
	    listenAddr: string;
	    powToken: string;
	
	    static createFrom(source: any = {}) {
	        return new UINodeInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nodeId = source["nodeId"];
	        this.listenAddr = source["listenAddr"];
	        this.powToken = source["powToken"];
	    }
	}
	export class UIPeer {
	    id: string;
	    addr: string;
	    reputation: number;
	    latencyMs: number;
	
	    static createFrom(source: any = {}) {
	        return new UIPeer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.addr = source["addr"];
	        this.reputation = source["reputation"];
	        this.latencyMs = source["latencyMs"];
	    }
	}

}

