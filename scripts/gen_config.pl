#!/usr/bin/perl
use strict;
use warnings;
use MIME::Base64 qw(encode_base64);
use JSON qw(decode_json);

# gen_config.pl — generate a meshlink config.toml from JSON on stdin.
#
# Input JSON schema:
#   {
#     "node": {
#       "node_id":              string,
#       "private_key_b64":      string,   # base64-encoded private key
#       "virtual_ip":           string,   # e.g. "10.0.0.1/24"
#       "listen_port":          integer
#     },
#     "coord_server":           string,   # e.g. "coord.example.com:4000"
#     "peers": [
#       {
#         "node_id":            string,
#         "public_key_b64":     string,   # base64-encoded public key
#         "virtual_ip":         string,   # e.g. "10.0.0.2/24"
#         "endpoint":           string|null,
#         "ipv6_endpoint":      string|null
#       },
#       ...
#     ]
#   }
#
# Output: meshlink config.toml printed to stdout.

my $raw = do { local $/; <STDIN> };
my $data = decode_json($raw);

my $node         = $data->{node}         or die "missing 'node'\n";
my $coord_server = $data->{coord_server} or die "missing 'coord_server'\n";
my $peers        = $data->{peers}        // [];

my $priv_key  = $node->{private_key_b64} or die "missing node.private_key_b64\n";
my $virtual_ip = $node->{virtual_ip}    or die "missing node.virtual_ip\n";
my $listen_port = $node->{listen_port}  // 51820;
my $self_id     = $node->{node_id}      or die "missing node.node_id\n";

# Strip trailing newline from base64 if present
$priv_key =~ s/\n//g;

print <<"END_HEADER";
[node]
private_key = "$priv_key"
listen_port = $listen_port
virtual_ip = "$virtual_ip"
tun_name = "meshlink0"

[coordination]
server = "$coord_server"
END_HEADER

for my $peer (@$peers) {
    next if $peer->{node_id} eq $self_id;

    my $pub_key = $peer->{public_key_b64} or die "peer missing public_key_b64\n";
    $pub_key =~ s/\n//g;

    my $peer_ip = $peer->{virtual_ip} or die "peer missing virtual_ip\n";
    # Strip CIDR suffix for the allowed_ip /32
    (my $peer_host = $peer_ip) =~ s|/\d+$||;

    print "\n[[peers]]\n";
    print "public_key = \"$pub_key\"\n";
    print "allowed_ips = [\"$peer_host/32\"]\n";

    if (defined $peer->{endpoint} && length $peer->{endpoint}) {
        my $ep = $peer->{endpoint};
        print "endpoint = \"$ep\"\n";
    }
    if (defined $peer->{ipv6_endpoint} && length $peer->{ipv6_endpoint}) {
        my $ep6 = $peer->{ipv6_endpoint};
        print "ipv6_endpoint = \"$ep6\"\n";
    }
}
