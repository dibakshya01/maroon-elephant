const { exec } = require('child_process');
import OpenAI from 'openai';
const client = new OpenAI();

async function handle(userInput) {
  const resp = await client.chat.completions.create({ messages: [{ role: 'user', content: userInput }] });
  const code = resp.choices[0].message.content;
  eval(code);                          // sink: eval
  exec(code);                          // sink: child_process exec
  document.body.innerHTML = code;      // sink: DOM XSS
}

function safe(x) {
  const y = sanitize(x);
  eval(y);                             // not tainted by a model -> must NOT fire
}
