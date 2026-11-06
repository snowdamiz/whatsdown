import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Text, View } from 'react-native';
import { ConversationRow, RequestRow } from '../src/ui';

function RequestRowFixture() {
  const [opened, setOpened] = useState(0);
  const [accepted, setAccepted] = useState(0);
  const [control, setControl] = useState(0);
  return <View>
    <RequestRow name="@bob" preview="Can we talk about the project?" unread={2}
      onPress={() => setOpened(value => value + 1)}
      onAccept={() => setAccepted(value => value + 1)} />
    <Text>Opened: {opened}; accepted: {accepted}</Text>
    <ConversationRow name="@carol" preview="Existing conversation control" time="12:00"
      blocked={false} verified={false} keyChanged={false}
      onPress={() => setControl(value => value + 1)} />
    <Text>Control: {control}</Text>
  </View>;
}

createRoot(document.getElementById('root')!).render(<RequestRowFixture />);
