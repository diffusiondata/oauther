type Protocol = 'http' | 'https';
type Method =
    | 'get' | 'GET'
    | 'delete' | 'DELETE'
    | 'head' | 'HEAD'
    | 'options' | 'OPTIONS'
    | 'post' | 'POST'
    | 'put' | 'PUT'
    | 'patch' | 'PATCH'
    | 'purge' | 'PURGE'
    | 'link' | 'LINK'
    | 'unlink' | 'UNLINK';
type SignatureMethod = 'HMAC-SHA1' | 'PLAINTEXT';

interface OAutherConfig {
    consumer?: {
        key: string,
        secret: string
    },
    token?: {
        key: string,
        secret: string
    },
    signature_method?: SignatureMethod,
    nonce_length?: number
}

interface Signature {
    toObject(): SignatureObject,
    toHeader(): string,
    toForm(): string
}

interface SignatureObject {
    oauth_signature_method: SignatureMethod,
    oauth_consumer_key: string,
    oauth_nonce: string,
    oauth_timestamp: number,
    oauth_version: string,
    oauth_signature: string
}

interface RequestDetails {
    baseUrl?: string,
    hostname?: string,
    protocol?: Protocol,
    port?: number,
    path?: string,
    method?: Method,
    body?: { [key: string]: any },
    query?: { [key: string]: any }
}

interface OAuther {
    /**
     * Sign OAuth request.
     * @param  {Object} request data
     * {
     *     hostname : 'example.com',
     *     method : 'GET',
     *     path : '/path/to/url',
     *     port : 80, // optional
     *     protocol : 'http', // optional, default 'http'
     *     query, : { 'gaius' : 'baltar' },// optional, query string as json
     *     body : { 'kara' : 'thrace' } // optional, form encoded body as json
     * }
     * @return {Object} OAuth data object
     */
    sign(request: RequestDetails): Signature,
    /**
     * A http request to validate
     * @param  {Object} request request
     * @return {Object} true if the signature is valid
     */
    validate(request: any): boolean;
}

declare function oauther(config: OAutherConfig): OAuther;
export = oauther;
