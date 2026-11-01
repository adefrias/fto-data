'use strict';
const { neon } = require('@neondatabase/serverless');
const { makeHandler } = require('../lib/handler');
const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
const sql = url ? neon(url) : null;
module.exports = makeHandler(async (text, params) => {
  if (!sql) throw new Error('DATABASE_URL is not set');
  return sql.query(text, params || []);
});
