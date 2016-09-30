% Title = "Protocol for bypassing challenge pages using RSA blind signed tokens"
% abbrev = "Protocol for bypassing challenge pages"
% category = "info"
% docName = "draft-protocol-challenge-bypass-00"
% ipr= "trust200902"
% area = "Internet"
% workgroup = "Network Working Group"
% keyword = [""]
%
% date = 2016-09-13
%
% [pi]
% toc = "yes"
%
% #Independent Submission
% [[author]]
% initials="A."
% surname="Davidson"
% fullname="Alex Davidson"
% organization = "Royal Holloway, University of London"
%   [author.address]
%   email = "alex.davidson.2014@live.rhul.ac.uk"
%   [author.address.postal]
%   street = "Egham Hill"
%   city = "Egham"
%   code = "TW20 0EX"
%
% [[author]]
% initials="N."
% surname="Sullivan"
% fullname="Nick Sullivan"
% organization = "CloudFlare"
%   [author.address]
%   email = "nick@cloudflare.com"
%   [author.address.postal]
%   street = "101 Townsend St"
%   city = "San Francisco"
%   code = "CA 94107"
%
% [[author]]
% initials="G."
% surname="Tankersley"
% fullname="George Tankersley"
% organization = "coreOS"
%   [author.address]
%   email = "george.tankersley@gmail.com"
%
% [[author]]
% initials="F."
% surname="Valsorda"
% fullname="Filippo Valsorda"
% organization = "CloudFlare"
%   [author.address]
%   email = "filippo@cloudflare.com"
%   [author.address.postal]
%   street = "25 Lavington Street"
%   city = "London"
%   code = "SE1 0NZ"


.# Abstract

This document proposes a protocol for bypassing challenge pages (such 
as forms requiring CAPTCHA submissions) that are served by edge 
services in order to protect origin websites. A client is required to 
complete an initial challenge and is then granted signed tokens which
can be redeemed in the future to bypass challenges and thus meaning 
that honest users undergo less manual computation. The signed tokens 
are cryptographically unlinkable to prevent future requests being 
linked to the original signed set of tokens.

{mainmatter}

# Introduction

Various challenge pages are used to distinguish human access to a 
website from automated access, with the intention of preventing 
malicious behaviour that could compromise the website that is being 
hosted. CAPTCHAs ("Completely Automated Public Turing test to tell 
Computers and Humans Apart") [@!ABHL03] are one of the most widely 
used methods for distinguishing human access to a resource from 
automated access. CAPTCHAs are regularly deployed as "interstitial"
pages forcing a user to answer the CAPTCHA before access is given to 
a website that was requested by the user. This is used to prevent 
malicious access by automated processes that can adversely affect the 
performance of the website itself. While these 'challenges' succeed in 
their mission statement, they do add a noticeably extra amount of work
to honest users who have to complete them.

These challenge pages are commonly enforced by CDNs who offer security
services to customers. Companies like CloudFlare offer the ability for 
customers to serve CAPTCHA pages (via Google's ReCAPTCHA service) to 
any IP addresses requesting a protected resource where the IP is 
deemed to have a "bad reputation". IP reputation scoring is done 
externally and is based on whether any malign activity (such as 
spamming and/or abuse) is detected as originating from this address. 

Services such as Tor suffer dramatically under such reputation-based 
systems. Users are assigned to one of a small number exit nodes when 
accessing webpages through Tor and thus they are assigned the IP of 
the node itself. The IP addresses of these nodes are frequently 
associated with malicious and abusive behaviour and are thus assigned
poor reputation scores. This can also effect other services such as 
VPN providers and I2P traffic.

The end result is that honest users of services like Tor are forced to 
complete many challenge pages in order to access content provided by 
edge service providers such as CloudFlare. This problem is exacerbated
by the fact that these companies typically offer services to a 
wide-range of websites including many of the most visited web pages on 
the internet today. This results in a huge increase in workload for 
these users for a very common and unobtrusive task. 

Further problems arise for users who choose not to enable JavaScript 
in their browsers since they are served with challenges that are 
rapidly deteriorating to the point where a large proportion of 
challenges are too hard to be solved.

Currently some edge providers (e.g. CloudFlare) attempt to solve this 
problem by providing cookies that enable access to protected resources 
once a CAPTCHA has been solved. There are two problems with this 
method:
- when a new Tor circuit is constructed the cookie is rendered 
  useless;
- due to a CDN's sprawling presence, giving users cookies can lead to 
  future deanonymisation attacks that bypass the current Tor threat 
  model.
As such a new solution to this problem is needed.

In this document we detail a protocol that enables a user to complete
a single edge-served challenge page in return for a finite number of 
signed tokens. These tokens can then be used to bypass future 
challenge pages that are served by participating edge-providers. The 
tokens are generated in such a way that signed tokens cannot be linked
to future redeemed tokens for bypassing. We achieve this using the RSA
blind signature scheme first presented by David Chaum [@?Cha83]. 

## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this
document, are to be interpreted as described in [@?RFC2119].

The following terms are used:

edge: A serving endpoint that provides access to a protected origin.

client: The endpoint attempting to access an edge-protected service.

origin: The endpoint where web content is stored.

edge-protected: Term for origins that pay the edge to provide 
protection services for their domain.

endpoint: Points where requests and responses are dealt with.

browser: A program ran by the client that provides access to webpages.

plugin: An installed service that runs in the client's browser.

tokens: JSON structures that are generated by the plugin in the 
client's browser for future redemption.

blinding: An operation that "hides" the contents of the token while 
still allowing the underlying token to be cryptographically signed.

unblinding: The reverse procedure of blinding. Recovers a token and
(if signed) a valid signature on the token.

challenge answer: Generated when submitting a response to a given 
challenge.

challenge page: A page generated by the edge for the client. The 
client must answer a challenge on the page correctly and return it to
gain access to a particular resource.

nonce: A randomly sampled value that is used for generating unique
tokens.


# Protocol Overview

Our protocols are initiated when a client is presented with a 
challenge page that contains additional information indicating that 
the edge service accepts tokens for bypassing the challenge. This can 
be indicated in the HTML of the page as a meta tag along with a 
certificate advising which public key the edge is currently using.
Two separate protocols exist for when the client has no signed tokens
available to them and secondly when the client already has tokens.

Both protocols require essentially four rounds of communication. We 
take into account the initial request and response when the client 
attempts to visit an edge-protected origin and is served a challenge 
page instead.

## Acquiring Signed Tokens

{#fig-sign-toks-full}
~~~

       Client                                            Edge
    
       [OriginRequest]         ------->                      
                                                ChallengePage  ^                                                                      
                                                 + bypass_tag  |
                                               + sig_key_cert  |
                               <-------            [Response]  v
    ^  VerifyCertificate
    |  GenerateTokens
    v  BlindTokens
    ^  SolveChallenge
    v  [SignRequest]           ------->        
                                              VerifyChallenge  ^
                                                   SignTokens  |
                               <-------            [Response]  v
    ^  VerifySigs
    |  UnblindTokens
    |  StoreTokens
    v  [Finished]

~~~
Figure: Full message flow for acquiring signed tokens


When a client attempts to visit an edge-protected origin the edge can 
indicate that it accepts tokens for bypassing a challenge page in 
exchange as well as presenting a certificate corresponding to their 
current signing key. In this event the client does the following:

- checks that the certificate is valid and that the signature 
  verifies correctly;
- checks that it is aware of the public key provided (e.g. that the 
  key is pinned in the plugin);
- generates N tokens and blinds them;
- sends the tokens to the edge along with an answer to the 
  challenge.

In practice N =< 100 so as not put too much work on the browser, 
limiting to this number also mitigates DDoS potential. After receiving 
the tokens and the answer to the challenge the edge does the 
following:

- checks that the answer is correct;
- if this is the case then it signs the tokens and returns the 
  signatures to the client.

The client does not immediately get access to the origin, though this
can be achieved if the client immediately reloads the page and redeems
a token using the process below. The client participates in some final
post-processing:

- they check that the signatures verify correctly with respect to the 
pinned public key and the blinded token;
- they unblind the token and signature pair to get a new pair of the 
original token and a valid sigature;
- they finally store the pair in their browser plugin for future use.


## Redeeming Tokens

{#fig-redeem-toks-full}
~~~

       Client                                            Edge
    
       [OriginRequest]          ------>                      
                                                ChallengePage  ^                                                                      
                                                 + bypass_tag  |                                                 
                                               + sig_key_cert  |
                                <------            [Response]  v
    ^  VerifyCertificate
    |  ConstructTokenMessage
    |  ProofOfWork*
    v  [SendToken]              ------>   
                                                   VerifyPoW*  ^   
                                           VerifyTokenMessage  |
                                                    GetOrigin  |
                                <------            [Response]  v
       [Finished]

~~~
Figure: Full message flow for redeeming tokens

* - optional extensions to the protocol

As before the client attempts to visit an edge-protected website and 
is faced with a challenge page. If the edge accepts tokens and 
provides a certificate that corresponds to a key that the client has 
pinned in their plugin and they have tokens signed by the counterpart 
private key then the client can attempt to bypass the prospective 
challenge page. This process is as follows:

- client constructs and sends a message containing:
  - an encrypted, unused token;
  - a valid signature for the token;
  - a HMAC, keyed by the token and computed over message identifying 
  information;
- edge receives the message and performs the following checks:
  - decrypts the token and checks that it resembles an agreed 
  structure, else the protocol is aborted;
  - checks if the token has already been used, if so the protocol is 
  aborted; 
  - verifies the signature on the unencrypted token;
  - validates the HMAC using the token as a key and unique message 
  information as input;
- If all checks pass the edge allows the client access to the 
originally requested origin.

# Preliminaries 

## Protocol Communication

We assume that our protocol is carried out over HTTP. This is a 
natural choice for the medium of communication given that the protocol
is initiated by a client who is accessing a URI over the internet. 
Due to this assumption we may refer to messages between the client and
the edge as HTTP requests and responses respectively. This also helps 
us to elaborate on particulars of the protocol that are intrinsically
linked to this method of communication. 

However, while the original intention of this protocol is for 
bypassing challenge pages over HTTP we encourage usage of the idea to 
any scenario where the receiving of unlinkable "currency" is an 
appropriate reward for completing some pre-defined challenge. The 
message format of the protocol is not strictly required to be HTTP as 
long as no structural changes are made to the messages that are sent.

## Design Formation

To explain the concepts in our design we will use a variety of 
structures that are most easily exposed using an easily readable code 
syntax. 

### Variables and Functions

Variables and functions follow the syntax of C-like languages, 
such as:

    int apple = 7;

where `int` is the type of the variable 'apple' and 7 is the value 
assigned to it. All types are self-explanatory and follow convention 
apart from:

- `int_b`: Used for large integers when undergoing cryptographic 
operations in large groups.
- All arrays will be denoted by a set of square brackets followed by 
the type of data that is contained. For example an array of strings 
will be described as: 

    `[]string`

- We call key-value stores 'maps' and define them as:

    `map[type_1](type_2)`

where type_1 is the type of the keys for the map (e.g. string) and 
type_2 is the type of the stored values (e.g. int).

We avoid type declaration when defining functions in favour of a 
textual explanation.

### Structs

We use structs to define a closed ecosystem (similar to an object) 
with a list of variables and functions that define the struct. We 
describe structs using the syntax:

    struct Person {
      var (
        string name;
        int age;
        map[string](string) emailAddresses;
      );

      func (
        setAge(n int);
        changeName(name string);
        addEmail(email string);
      )
    }

this gives us an interface with which we can interact with the struct,
allowing us to store and access data with respect to this definition.
Here, `vars` defines a list of variables stored on the struct, while 
`func` defines a list of functions that require implementation.

### JSON Objects

We use JSON objects for representing tokens and for constructing 
messages for sending from the client to the edge. We define our JSON 
structures as:

    {
      "key_1":"[value_1]"
      "key_2":"[value_2]"
            .
            .
            .
      "key_n":"[value_n]"
    }

where each `"key_i"` is a key value, key_i is marshaled as a string 
but can be any built-in type. Likewise `"[value_i]"` represents the 
corresponding value for `"key_i"`, `value_i` is typically encoded as a 
string in either hexadecimal or base-64 encoding. We assume that all 
JSON is accessible using a map-interface where, if data is a JSON 
object, then `data[key_1]` returns `value_1`.

## Data Formatting

This section deals with the formatting of the different data types 
that are required in our protocol. This will cover, for instance, how 
tokens should be formatted and how messages between the client and the
edge should be structured.

### Tokens

Tokens are JSON-like structures containing a single nonce field, i.e.

    {
      "nonce":"[nonce_value]"
    }

where [nonce_value] is a hex encoded 30-byte sequence of 
cryptographically random bytes.

### Client-Edge Message Format

The messages that the client sends to the edge after being served a 
challenge page (i.e. in the third round of communication) are written
as JSON structures. These messages designate the type of operation 
that is required of the edge. All messages below are base-64 encoded 
before they are sent. 

The messages are heavily defined by the HTTP protocol that the 
client-edge interaction takes place over. For example, the signing 
messages detailed below are included in the body of a HTTP request due 
to artificial limits placed on HTTP header field sizes by web servers. 
Likewise the redemption messages are significantly smaller and are 
thus included in a header. This difference in transport architecture
leads to differences in the message formats shown below. 

#### Signing

In the first protocol, when the client sends an answer to the given 
challenge page they can also append a JSON object to the of the form:

    {
      "type":"Signing",
      "contents":"[t'_1],[t'_2], ...,[t'_N]"
    }

where [t'_i] is a generated token that has been subsequently blinded. 
We call such a JSON object a 'JSON signing request' (JSR).

After base-64 encoding is done the final message is sent to the edge 
as:

    blinded-tokens=[base-64 encoded JSR]

#### Redeeming

In the second protocol when the client attempts to bypass a challenge 
they send a message containing a JSON object of the form:

    {
      "type":"Redeem",
      "contents":"[<encrypted_token>,<signature>,<HMAC>]"
    }

where the token that is encrypted has been since unblinded. Such an 
object is known as a 'JSON redemption request' (JRR).

### Edge-Client Message Format

The messages returned by the edge to the client are much more heavily 
defined by the messaging protocol being used to communicate. For 
example, in the redemption protocol the server merely serves content 
from the origin in the event that the token that is redeemed verifies
correctly.

In the first protocol however the edge also returns a comma-separated
list:
    
    signatures=[s'_1],[s'_2],...,[s'_N]

where [s'_i] is a signature computed by the edge over the blinded 
token [t'_i] that it received along with a response to the challenge
page that was sent.

### Signature Transport Format

Signatures are sent between the client and the edge using the JWS 
format defined in [@?RFC7515]. The token that is signed is stored as 
the payload on the JWS object - thus when carrying out unblinding on 
the signature the payload must also be updated.

### Certificate Transport Format

Certificates can be transported via any standardised method for 
encoding a certificate (e.g. X.509v3 [@?RFC5280]). 

# Cryptographic Tools

To instantiate the protocols above we require a set of tools that
allows either participant to perform cryptographic operations over 
data. In this section we detail the materials and the algorithms that
are required in order to compute these operations.

## Keys

Our protocol requires two key pairs:

- edge identity keys (id-pub-key, id-priv-key): Used for performing 
the encryption and decryption required on the token that is sent for
redemption;
- edge signing keys (sign-pub-key, sign-priv-key): Used for performing
the signing and verification of signatures;
- A symmetric MAC key derived from the 'nonce' field on a token.

The edge holds both key pairs and the plugin in the client's browser 
has the public keys. The MAC key is derived at the time of messaging 
and is learnt by both parties.

## Signing/Verifying Algorithms

- SIGN(sign-priv-key, data) --> sig : takes a private signing key and 
some 'data' and returns a valid signature 'sig' on 'data'.
- VERIFY(sign-pub-key, data, sig) --> 'good'/'bad' : takes the a 
public verification key, some 'data' and a signature 'sig' and outputs
'good' if 'sig' is a valid signature on 'data'. Otherwise it outputs 
'bad'.

## Blinding/Unblinding Algorithms

- BLIND(blinding-factor, data) --> blind-data : takes a randomly 
sampled 'blinding-factor' and some 'data' and outputs 'blind-data' that 
is computationally unlinkable from 'data'.
- UNBLIND(blinding-factor, blind-data, blind-sig) --> (data, sig) : 
takes 'blind-data' and the randomly sampled 'blinding-factor' used to 
generate it, along with an optional parameter for a valid signature
'blind-sig' computed over 'blind-data' as input. Outputs 'data' and 
'sig' where 'data' is the unblinded counterpart to 'blind-data' and 
'sig' is a valid signature on 'data'.

## Encryption/Decryption Algorithms

- ENCRYPT(id-pub-key, plaintext) --> ciphertext : takes a public 
encryption key and a 'plaintext' as input and outputs an encrypted 
'ciphertext'.
- DECRYPT(id-priv-key, ciphertext) --> plaintext : takes a private
decryption key and an encrypted 'ciphertext' as input and outputs a
'plaintext'.


## MAC Algorithm

Our MAC algorithm has the following specification: 

- MAC(mac-key, data) --> mac : takes a symmetric mac-key and 'data' 
as input and outputs 'mac' as a valid authentication code on 'data'.

## Instantiation of Cryptographic Tools

In theory any digital signature scheme that allows for blind signing 
and unblinding operations can be used to instantiate our requirements.
However, due to the simplicity of its design we have chosen to only 
support the RSA blind signing modification (RSA-blind) shown in 
[!@Cha83]. We may benefit by adding support for elliptic curve based 
designs in the future to decrease the size of messages in our 
protocol.

By choosing RSA-blind we make the following parameter choices:

- both encryption and signing keys are 2048-bit RSA keys;
- the SIGN/VERIFY algorithms are RSA without modifications;
- BLIND/UNBLIND follow naturally from the referenced work;
- ENCRYPT/DECRYPT are instantiated with RSA-OAEP;
- MAC is instantiated with HMAC.

To mitigate the issues caused by using RSA without modifications we 
make extra structural checks on the tokens that are sent -- this is to 
prevent manipulation of tokens using the homomorphic properties of 
this scheme. Also all tokens must be representable in less than 2048 
bits to prevent problems with wrapping-around the RSA modulus.

## Randomness Sampling

Finally we require an ability for the browser plugin to sample 
random values for blinding tokens. Our algorithm can be thought of as:

- SAMPLE(seed) --> rand : takes a random seed as input and generates a
value 'rand'.

we can instantiate this algorithm using any standard library for 
generating cryptographic randomness. In future notation we may omit  
the seed for ease of exposition.

# Browser plugin

To participate in the protocol, the client must be using a browser 
with an installed and validated browser plugin. This plugin controls 
the generation, blinding, unblinding, storage and redemption of tokens 
for bypassing challenge pages. The browser plugin can be thought of as
a struct with the following attributes:

    struct Plugin {
      var (
        map[string]([]string) tokens;
        map[string](string) signatures;
        map[string](int_b) blindingFactors;
        []string publicKeys;
      )

      func (
        parse(string s, string p);
        verifyCert([]byte pk, []byte cert);
        verifySig([]byte pk, []byte s, []byte t);
        generate(int N);
        blind(string t);
        unblind(string t', string s', int_b r);
        store(string pubKey, []string tokens, []string sigs);
        encode(string type, []string data);
        mac([]byte nonce, string s);
        send(string msg);
        pow([]byte randNonce);
      )
    }

We implement the struct functions in the following way.

- parse(s, p) --> b

This function takes strings s, p as output and returns a boolean 'b' 
where "b == true" if p is a valid substring of p. Otherwise "b == 
false".

- verifyCert(pubKey, cert) --> b

This function takes the bytes of a public verification key 'pubKey' 
and a certificate 'cert' as input and outputs a boolean value b, where 
"b == true" if the signature on 'cert' can be verified correctly and 
the public key on 'cert' is pinned in contained in 
`Plugin.publicKeys`. Otherwise "b == false". The VERIFY() algorithm is
used to ascertain whether the signature is valid over the inputs to 
this function. 

Other details on the certificate are also verified in this step (for
example that the expiry date has not elapsed and that the provider is
consistent with the protecting edge).

- verifySig(pubKey, s, t) --> b

This function takes the bytes of a public verification key 'pubKey', a
token 't' and a signature 's'. It outputs "b == true" if 's' is a 
valid signature on t and "b == false" otherwise. The plugin runs
VERIFY() using all three inputs to get the output b and returns this 
as the output of the function.

- generate(N) --> tokens

This function takes an integer N as input and outputs an array 
'tokens' of length N containing. The array is generated by sampling N 
30-byte nonces is randomly sampled via SAMPLE() and constructing N 
tokens by creating N JSON objects with the "nonce" field set to the 
value of the sampled nonce.

- blind(t) --> t'

This function takes a token t as input and outputs a blinded token t'.
The function uses SAMPLE() to generate a 256-byte random `int_b` r and 
then runs BLIND(r, t) --> t' and outputs t'. It also sets 
  
    Plugin.blindingFactors[t'] = r 

- unblind(t', s', r) --> (t, s)

Takes a blinded token t', a valid signature s' for t' and the blinding 
factor r as input and outputs a pair (t, s) where t is the unblinded 
token and s is a valid signature on t. The function uses the algorithm 
UNBLIND(r, t', s') to retrieve (t, s).

- store(pubKey, tokens, sigs) 

This function does not return anything. It simply sets 

    Plugin.tokens[pubKey] = tokens

and

    Plugin.signatures[tokens[i]] = sigs[i]

- encode(type, data)

Takes a 'type' string and a base-64 encoded string 'data' as input. 
The 'type' string corresponds to a JSON request (either "JSR" or 
"JRR") and creates a JSON object with the "type" field set 
appropriately and the "contents" field set to be equal to the 'data' 
input.

- mac(nonce, s) 

Takes 'nonce' in byte form and a string 's' as input. The 'nonce' 
value is used as the key and 's' is the contents to be computed over.
This function runs the algorithm MAC(nonce, s) on the two inputs and
outputs whatever this algorithm outputs.

- send(msg)

Provides no output, takes a string representation 'msg' as input where 
'msg' is either a JSR or JRR as input. This function reloads the 
current page in the browser and appends 'msg' in the HTTP request that
is created (either in a header or in the body).

- pow(randNonce)

Optional method for the plugin. Takes the bytes of a random nonce 
'randNonce' as input and computes some proof-of-work computation that
is specified by the edge. The output is given as 'out' and is used by 
the client in the following bypass request that is made.

## Pinned public keys

The plugin has a list of public keys pinned into it in the string 
array `publicKeys` (the keys are stored as hex strings). This prevents 
a service from handing out unique public keys for each client and thus 
gaining request linkability and a deanonymisation vector on users. 
When an edge provides a certificate for a given public key the plugin 
checks if the key that is contained in the certificate is one of the
pinned keys that it already has stored before continuing.

# Token Acquisition Protocol

The token acquisition protocol allows a client to acquire signatures
on client-generated tokens that can be redeemed in the future to 
bypass challenge pages. We analyse the protocol with respect to the 
stages that we defined in Figure 1.

## [OriginRequest]

This initiation of the protocol is triggered by the OriginRequest 
where the client attempts to access a webpage (for example over HTTP).
For the purposes of our protocol this webpage is edge-protected.

## ChallengePage

The edge deems the origin request to come from a client requiring the
showing of a challenge in order to grant access to the protected 
website. The challenge page displays some HTML conveying the explicit
challenge to the client.

To participate in accepting tokens for bypassing challenge pages, an 
edge must also append specific `<meta>` tags to the HTML of the page. 
The tags that indicate participation are:

~~~~
<meta name="captcha-bypass" id="captcha-bypass" />
<meta name="chl-cert" id="chl-cert" content="%s" />
~~~~

where '%s' is replaced with a valid certificate on some public key.

## VerifyCertificate

When a client is delivered such a page, the installed plugin will run 
the `parse()` function on the HTML and the meta tags above, if this 
function returns true then the plugin inputs the certificate from '%s'
into `verifyCert()` and checks that this also returns true. 

## GenerateTokens + BlindTokens

The plugin retrieves the public key 'pubKey' from the verified 
certificate and then checks if `Plugin.tokens[pubKey]` is empty or 
not. 

If there are no tokens stored for 'pubKey' the plugin runs 
`generate(N)` to get an array of N 'toks'. It then runs `blind(t)` on 
each token and constructs an array of blinded tokens, 'blindedTokens'. 
The array 'toks' is stored in the 'tokens' map as 
    
    tokens[pubKey] = toks

where 'pubKey' is the public key from the certificate.

## SolveChallenge

This step involves the client solving the presented challenge. This 
step requires human intervention, for instance as in the way that 
CAPTCHAs are solved.

## [SignRequest]

The plugin encodes the array 'blindedTokens' as a string 'content' and 
runs `encode("JSR", content)` to get a JSR request containing this 
data. When the challenge solution is sent to the edge by the client, 
the plugin base-64 encodes the JSR and appends it to the HTTP request 
body using the syntax:

    blinded-tokens=<base-64 encoded JSR>

## VerifyChallenge

When the edge receives the request with a challenge solution and a JSR
it first checks that the solution provided is correct with respect to 
the initial challenge that was sent.

## SignTokens

The edge receives the blinded tokens, checks that the challenge 
solution is valid and then runs SIGN() on each blinded token t'_i from 
the JSR using the private signing key `sig-priv-key` that it owns. The
edge constructs an array 'sigs' from the signatures that are produced 
by the SIGN() algorithm.

## [Response]

The edge responds to the client with an array containing the pairs of 
blinded tokens with their respective signatures from the array 'sigs'
using the syntax:

    signatures=[<s'_1>,...,<s'_N>]

where each `<s'_i>` is a base-64 encoded JWS object containing the 
blinded token that is signed as the payload.

## VerifyingSignatures

The client receives the comma-separated signatures from the edge. 

Firstly, the plugin runs `verifySig(pubKey, s'_i, t'_i)` for the ith 
received signature `s'_i` where `t'_i` is the blinded token stored in 
the payload and pubKey stored on the original certificate. If each 
invocation of `verifySig()` is successful then the plugin proceeds.

## UnblindTokens

Secondly the plugin runs `unblind(t'_i, s'_i, r_i)` where r_i is the 
ith blinding factor stored in `Plugin.blindingFactors`. This function 
outputs the pair `(t_i, s_i)`.

## StoreTokens

Finally the plugin checks that:

    Plugin.tokens[pubKey][i] = t_i

If so, then the plugin runs `store(pubKey, t_i, s_i)` to store the 
token and signature for future use. 

# Challenge Bypass Protocol

The challenge bypass protocol starts in the same way as the token
acquisition protocol with the client attempting to visit an 
edge-protected origin. The origin returns a challenge page as before
and the client's browser verifies the HTML `meta` tags sent by the 
edge indicate that bypassing a challenge page can happen. The protocol 
deviates after the VerifyCertificate stage if the map 
`Plugin.tokens[pubKey]` is populated by one or more tokens (where 
'pubKey' is the certified public key as before). 

We detail the steps that follow this stage in detailing how a client 
can bypass the challenge.

## ConstructTokenMessage

When the client has tokens for being able to bypass challenges the 
browser plugin does the following:

- picks the next available token and signature pair (t,sig) for 
'pubKey' where:

~~~~    
pubKey = sig-pub-key;
~~~~

- encrypts t by computing 

~~~~    
ENCRYPT(id-pub-key, t) --> t-enc;
~~~~

- computes 

~~~~
MAC(t["nonce"], unique-request-data) --> hm
~~~~

where the MAC algorithm is keyed by the "nonce" field on the token and
'unique-request-data' is some data that is unique to a request 
containing this token;

- creates a concatenated string:

~~~~
t-enc || sig || hm
~~~~

and base-64 encodes it to form a base-64 string 'data';

## ProofOfWork

This is an optional extension to the protocol that enables the edge to 
specify some proof-of-work (PoW) computation to the client. This is to 
prevent any client from being able to construct many viable-looking,
but invalid, tokens that force the edge into computing a number of 
public-key operations before throwing away the invalid token. If done 
often enough this could lead to a potential DDoS vector on the edge.
By establishing a PoW step this limits the client to only being able 
to redeem tokens when they can answer the PoW.

If this step is to be used, the edge specifies an extra header in the 
initial response to the client with the attribute 
"bypass-proof-of-work" and a value "randNonce" that contains a random
nonce that the client uses in answering the PoW. The plugin then 
computes `pow(randNonce)` --> 'out' where 'out' represent the output 
of the computation.

## SendToken

- Runs encode("JRR", data) to get a JRR with the "contents" field set 
equal to 'data'
- If ProofOfWork is done, then the plugin appends an extra field to 
the JRR object named "pow" where the value is equal to 'out'.

The plugin then reloads the page and sends this JRR as the value of 
the header "challenge-bypass-token".

## VerifyPoW

When the edge receives the JRR message that was sent above, if a PoW 
was stipulated then the edge first checks that the value stored in the 
"pow" field is correct for the random nonce that was sent.

If not, then the protocol is aborted at this point.

## VerifyTokenMessage

The edge decodes the "contents" fields from the received JRR and it 
does the following:

- sets a "success" bool to true;
- computes

~~~~
DECRYPT(id-priv-key, t-enc) --> t
~~~~

and checks that t is a JSON object with a "nonce" field, if either 
check fails then set "success" equal to false;
- checks that t has not been redeemed before, otherwise set "success" 
to false;
- computes

    VERIFY(sig-pub-key, t, sig) --> b

if 'b' is not true then it sets "success" to false;
- retrieves 'edge-request-data' from the request it received and 
computes

    MAC(t["nonce"], edge-request-data) --> hm-edge

and checks that hm == hm-edge, if not "it sets "success" to false.

If "success" is still true, then the edge marks the bypass request as 
successful and continues. 

## GetOrigin + [Response]

If the verification process was successful. The edge gets a response 
from the origin that corresponds to the original request in 
{OriginRequest} from the client. The edge then sends this response 
directly back to the client.

This allows the client access to the resource they tried to gain 
access to. 


<reference anchor='Cha83' target='http://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF'>
  <front>
   <title>Blind Signatures For Untraceable Payments</title>
   <author initials='D.' surname='Chaum' fullname='David Chaum'></author>
   <date year='1983' />
  </front>
</reference>

<reference anchor='ABHL03' target='https://www.cs.cmu.edu/~mblum/research/pdf/captcha.pdf'>
  <front>
   <title>CAPTCHA: Using Hard AI Problems For Security</title>
   <author initials='L.' surname='von Ahn' fullname='Luis von Ahn'></author>
   <author initials='M.' surname='Blum' fullname='Manuel Blum'></author>
   <author initials='N. J.' surname='Hopper' fullname='Nicholas J. Hopper'></author>
   <author initials='J.' surname='Langford' fullname='John Langford'></author>
   <date year='2003' />
  </front>
</reference>

{backmatter}