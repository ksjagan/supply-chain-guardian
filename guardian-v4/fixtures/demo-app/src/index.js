const express = require('express');
const lodash = require('lodash');
const app = express();

app.get('/', (req, res) => {
  res.send('Software Supply Chain Guardian Demo App');
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Demo app running on port ${PORT}`);
  });
}

module.exports = app;
