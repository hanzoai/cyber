declare module '*.css';
declare module '@hanzo/font/css';

interface HanzoCyberRuntimeConfig {
  apiBase?: string;
  iamHost?: string;
  ensoHost?: string;
}

interface Window {
  __HANZO_CYBER_CONFIG__?: HanzoCyberRuntimeConfig;
}
