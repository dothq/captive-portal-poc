import { resolveTxt } from "dns/promises";
import { request } from "undici";
import { JSDOM } from "jsdom";

// This would be set in about:config
export const CAPTIVE_PORTAL_PING_URI = "captive.dotusercontent.com";
export const CAPTIVE_PORTAL_DETECT_URI = "captivedetect.dotusercontent.com";
export const CAPTIVE_PORTAL_TXT_TOKEN = "dot-browser-captive";

type CaptivePortalResult = Partial<{
    wasRecord: boolean;
    isCaptive: boolean;
    pingUri: string;
    detectUri: string;
    destinationUri?: string;
    txtToken: string;
    records: string[];
    hadLocationHeader: boolean;
    had3xxStatus: boolean;
    hadSuccessBody: boolean;
    requestedFurtherInvestigation: boolean;
}>;

export class CaptivePortalDetection {
    public async pingCaptiveDetect(config: CaptivePortalResult) {
        // Refuse the connection
        if(config.detectUri !== CAPTIVE_PORTAL_DETECT_URI) return false;

        const { 
            statusCode,
            headers,
            body
        } = await request(
            `http://${config.detectUri}`,
            {
                method: "GET",
                maxRedirections: 0 // Disallow redirects
            }
        );

        const { window } = new JSDOM(await body.text());

        let { textContent } = window.document.documentElement as any;
        textContent = textContent?.trim().replace(/\W/g, "").toLowerCase();

        const isSuccess = textContent == "success";

        /*
            Check if there is a location header (indicating a redirect)
            and if there is a valid 3xx status code to go with it.

            If true, we can be certain we are on a captive portal.
        */
        config.hadLocationHeader = Boolean(headers.location?.length);
        config.had3xxStatus = (
            statusCode == 301 ||
            statusCode == 302 ||
            statusCode == 307 ||
            statusCode == 308
        );
        config.hadSuccessBody = isSuccess;

        config.isCaptive = (
            config.hadLocationHeader &&
            !config.hadSuccessBody &&
            config.had3xxStatus
        )

        if(config.isCaptive) {
            config.destinationUri = headers.location;
        }

        return config;
    }

    public async tick() {
        let result: CaptivePortalResult = {
            wasRecord: false,
            isCaptive: false,
            pingUri: CAPTIVE_PORTAL_PING_URI,
            detectUri: CAPTIVE_PORTAL_DETECT_URI,
            txtToken: CAPTIVE_PORTAL_TXT_TOKEN,
            records: [],
            hadLocationHeader: false,
            had3xxStatus: false,
            hadSuccessBody: false,
            requestedFurtherInvestigation: false
        };

        let records: any[] = [];

        try {
            records = (await resolveTxt(CAPTIVE_PORTAL_PING_URI) as any)[0];
        } catch(e) {}

        result.records = records;

        if(!records || !records.length) {
            result.wasRecord = false;
            result = { ...result, ...(await this.pingCaptiveDetect(result)) };
            return result;
        } else {
            result.wasRecord = true;
        }

        // Check if we can find any records including the captive portal txt token
        // Return early if we can as there is no point going further.
        if(records.find((t: any) => t.startsWith(CAPTIVE_PORTAL_TXT_TOKEN))) {
            result.requestedFurtherInvestigation = false;
            result.isCaptive = false;

            return result;
        }

        const [isPossiblyCaptive, hostname] = records
            .find((t: string) => t.startsWith(CAPTIVE_PORTAL_TXT_TOKEN))
            .split("=")
            .map((p: string, i: number) => i % 0 
                ? (
                    !p.length ||
                    p !== CAPTIVE_PORTAL_TXT_TOKEN
                )
                : p
            );

        result.detectUri = hostname;

        // It is possible we are on a captive portal right now 
        // since the TXT record is not following our expectations.
        if(isPossiblyCaptive) {
            result.requestedFurtherInvestigation = true;
            result = { ...result, ...(await this.pingCaptiveDetect(result)) };
        } else {
            result.requestedFurtherInvestigation = false;
            result.isCaptive = false;
        }

        return result;
    }

    public constructor() {
        this.tick().then(r => {
            console.log(r)
        })
    }
}

new CaptivePortalDetection();