import { useEffect, useState } from 'react';
import { Text } from 'react-native';
import { checkpointAgeSeconds } from './anchor';
import { useI18n } from './language';
import { useTheme } from './theme';

// Mounted only while details are open. Age changes locally; it never starts a
// network check or changes the native consistency/slash verdict.
export function AnchorCheckpointTime({ blockTime }: { blockTime: string }) {
  const { t } = useI18n();
  const { type } = useTheme();
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const seconds = checkpointAgeSeconds(blockTime, now);
  if (seconds === null) return <Text style={type.footnote}>{t('Public checkpoint time is unavailable.')}</Text>;
  const age = seconds < 60 ? t('{seconds}s ago', { seconds })
    : seconds < 3600 ? t('{minutes}m {seconds}s ago', { minutes: Math.floor(seconds / 60), seconds: seconds % 60 })
    : seconds < 86400 ? t('{hours}h {minutes}m ago', { hours: Math.floor(seconds / 3600), minutes: Math.floor(seconds / 60) % 60 })
    : t('{days}d {hours}h ago', { days: Math.floor(seconds / 86400), hours: Math.floor(seconds / 3600) % 24 });
  return <Text style={type.body}>{t('Last public checkpoint: {age}', { age })}</Text>;
}
