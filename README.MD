# Get My Miiverse Token!
Gets the Miiverse auth data (Service Token/Param Pack) for you
without having to mess with proxies on your Wii U.

## Why would i need this?
With the auth data extracted from your Wii U, you can access the
page that Miiverse on Wii U accesses, basically, Miiverse on Wii U is a web-based
applet, the way it works is that it sends two headers (X-Nintendo-ServiceToken, and 
X-Nintendo-ParamPack) with values of your NNID/PNID account, and like that it authenticates you.

## What is X-Nintendo-ServiceToken and X-Nintendo-ParamPack?
The first one, X-Nintendo-ServiceToken, contained an encrypted, well, token, with your
account data, and this is how the webpage that Miiverse loads identifies you (from now on, we are
gonna call this webpage "portal" as it is known by the URL)

The X-Nintendo-ParamPack header is really just a base64 encoded string full of metadata like your timezone, language, currently suspended game, access key, etc, you dont need to change it after the first time.

## Does any of these headers expire?
Yes, Pretendo added behavior for the Service Token to expire after a few hours, normally, it wouldnt expire ever as that is how it behaved on the original Nintendo Network servers, once your
token expires, the portal page will tell you, therefore you might need to open the app again and dump a new auth data file.

## (Pretendo Juxt users) Can i get banned from Juxt for using this?
Uhhhhhh, if you use this to abuse custom screenshots/custom memos or exploit the site in any way, then yes! yes it will.
This tool is only useful so you can access the Wii U version of the Miiverse portal site, as of the time of writing this, the only console Miiverse clone there is, is Juxt, which is very strict if you break the rules, specially the ones about API exploiting, so if you use this only to see communities/post as usual, i believe it will be fine, tho their rules can change at any time, so who knows?

## How the hell does this work? Never seen any homebrew apps use Miiverse, and it would be good if they did...
This app just calls nn::olv functions (Olive is the codename of Miiverse) in a raw way (assembly) from some simple reverse engineering that i did, that basically initializes it, and then gets the tokens, you can check the source code if youre interested, although i wish WUT just supported nn::olv by default