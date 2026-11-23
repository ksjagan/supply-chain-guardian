// Demo app entry point (not executed by Guardian)
const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const qs = require('qs');

const app = express();
app.get('/', (req, res) => res.send('Hello from demo-app'));
app.listen(3000);
