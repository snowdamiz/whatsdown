import App from "./App";
import { loadAppearance, saveAppearance } from "./appearance-store";
import { AppearanceProvider } from "./theme";

export default function Root() {
  return (
    <AppearanceProvider load={loadAppearance} save={saveAppearance}>
      <App />
    </AppearanceProvider>
  );
}
