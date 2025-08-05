document.getElementById('convertBtn').addEventListener('click', async () => {
  const inputText = document.getElementById('inputText').value.trim();
  const outputArea = document.getElementById('outputText');
  
  if (!inputText) {
    outputArea.value = 'Please enter a string to hash!';
    return;
  }
  
  outputArea.value = 'Hashing...';

  try {
    const response = await fetch('/cgi-bin/sha1.cgi', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'value=' + encodeURIComponent(inputText),
    });
    if (!response.ok) throw new Error('Network response was not OK');
    const hash = await response.text();
    outputArea.value = hash.trim();
  } catch (error) {
    outputArea.value = 'Error: ' + error.message;
  }
});
