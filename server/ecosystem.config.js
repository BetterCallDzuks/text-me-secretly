// PM2 process definition. Run with: pm2 start ecosystem.config.js
// See scripts/deploy.sh for the full VPS deploy/update flow.
module.exports = {
  apps: [
    {
      name: 'tms-server',
      script: 'server.js',
      cwd: __dirname,
      instances: 1, // in-memory peer map + mock payment store => single instance
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 10,
      watch: false,
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
      },
      // Logs land in ~/.pm2/logs by default; override here if desired.
      out_file: undefined,
      error_file: undefined,
      merge_logs: true,
      time: true,
    },
  ],
};
