# yodawgproxy

YO DAWG, I HEARD YOU LIKE PROXIES, SO I PUT A PROXY BEHIND YOUR PROXY SO YOU CAN FORWARD WHILE YOU FORWARD

## What does it do?

It receives TCP streams using the haproxy proxy protocol and proxies them to a backend, optionally tampering with them in the process (e.g. changing Host headers if it's HTTP and fiddling with SNI).

## License

License is AGPLv3.
