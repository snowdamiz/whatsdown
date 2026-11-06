// Expo installs React Native's globals and may replace fetch. Close those
// capabilities before evaluating app or headless notification task modules.
import 'expo';
import './src/network-lockdown-bootstrap';
import './src/background-notifications';
import { registerRootComponent } from 'expo';

import App from './src/Root';

registerRootComponent(App);
