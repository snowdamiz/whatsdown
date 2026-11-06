import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import vm from 'node:vm';
import { scopeFixture } from './scoped-test-fixture.mjs';
const require = createRequire(new URL('../package.json', import.meta.url));
const React = require('react'), jsx = require('react/jsx-runtime'), ts = require('typescript');
const { create, act } = require('react-test-renderer');
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const app = fileURLToPath(new URL('..', import.meta.url));
const boundary = values => new vm.SyntheticModule(Object.keys(values), function () {
  for (const [key,value] of Object.entries(values)) this.setExport(key,value);
});
async function fixture({ platform='android', origin={x:0,y:0,width:360,height:720}, window={width:360,height:720} } = {}) {
  const scoped=scopeFixture(), animations=[], focused=[];let extraWindows=0,currentInput=undefined;
  const Safe=React.createContext({top:0,bottom:0,left:0,right:0}), Keyboard=React.createContext('default');
  const Input=React.forwardRef((props,ref)=>{
    const input=React.useRef({focus(){currentInput=input.current;focused.push(props.accessibilityLabel);},blur(){if(currentInput===input.current)currentInput=undefined;},isFocused(){return currentInput===input.current;}});
    React.useImperativeHandle(ref,()=>input.current,[]);
    React.useLayoutEffect(()=>{if(props.autoFocus)input.current.focus();},[props.autoFocus]);
    return React.createElement('text-input',props);
  });
  Input.State={currentlyFocusedInput:()=>currentInput};
  class Value {
    constructor(value) { this.value=value; }
    setValue(value) { this.value=value; }
    interpolate(options) { return { value:this.value, ...options }; }
  }
  const animation = (value, options) => ({ start(done) { animations.push({ value, options, done }); }, stop() {} });
  const Animated = { Value, View:'animated-view', Text:'animated-text', Image:'animated-image',
    timing:animation, spring:animation, add:(left,right)=>({left,right}), createAnimatedComponent:value=>value };
  const NativeModal = ({ visible=true, children }) => {
    React.useLayoutEffect(() => { if (visible) extraWindows++; },[visible]);
    return visible ? React.createElement('extra-window',null,children) : null;
  };
  const View = React.forwardRef((props,ref) => {
    React.useImperativeHandle(ref,()=>({measureInWindow(done) { done(origin.x,origin.y,origin.width,origin.height); },focus() {}}),[]);
    return React.createElement('view',props,props.children);
  });
  const native = { Animated, Modal:NativeModal, PanResponder:{create:handlers=>({panHandlers:handlers})},
    ActivityIndicator:'activity-indicator',Clipboard:{setString(){}},Image:'image',Text:'text',TextInput:Input,Switch:'switch',Pressable:'pressable',Platform:{OS:platform,select:values=>values.android??values.default}, View,
    StyleSheet:{create:value=>value,flatten:value=>Object.assign({},...[value].flat(Infinity).filter(item=>item&&typeof item==='object')),absoluteFill:{position:'absolute',top:0,left:0,right:0,bottom:0},hairlineWidth:1},
    Easing:{bezier:()=>value=>value,out:value=>value,inOut:value=>value,cubic:value=>value},
    Appearance:{getColorScheme:()=> 'light',setColorScheme() {},addChangeListener:()=>({remove(){}})},
    useWindowDimensions:()=>({...window,scale:1,fontScale:1}),useColorScheme:()=> 'light' };
  const fonts = ['Geist_400Regular','Geist_500Medium','Geist_600SemiBold','Geist_700Bold','GeistMono_500Medium'];
  const ports = new Map([
    ['react',boundary({...React})],['react/jsx-runtime',boundary({...jsx})],['react-native',boundary(native)],
    ['react-native-safe-area-context',boundary({initialWindowMetrics:{insets:{top:24,bottom:16,left:0,right:0},frame:{x:0,y:0,...window}},useSafeAreaInsets:()=>React.useContext(Safe),SafeAreaProvider:props=>React.createElement(Safe.Provider,{value:props.insets??{top:24,bottom:16,left:0,right:0}},props.children)})],
    ['./keyboard',boundary({KeyboardAvoidingView:props=>React.createElement('keyboard-avoiding',{...props,keyboardContext:React.useContext(Keyboard),safeAreaBottom:React.useContext(Safe).bottom},props.children)})],
    ['expo-font',boundary({useFonts:()=>[true,null]})],
    ['react-native-qrcode-svg',boundary({default:'qr-code'})],
    ['react-native-svg',boundary(Object.fromEntries(['default','Circle','Defs','G','LinearGradient','Mask','Path','Pattern','RadialGradient','Rect','Stop'].map(name=>[name,'svg-'+name])))],
    ['./language',boundary({useI18n:()=>({t:Object.assign(key=>key,{plural:(_one,many)=>many}),locale:'en'})})],
    ['./glass',boundary({Glass:props=>React.createElement('glass',props,props.children),glassBackdrop:{},useLiquidGlass:()=>false,useMaterialized:()=>false})],
    ['./scroll',boundary({ScrollView:props=>React.createElement('scroll-view',props,props.children)})],
  ]);
  for(const name of fonts){const family=name.startsWith('GeistMono')?'geist-mono':'geist';const weight=name.split('_')[1];ports.set(`@expo-google-fonts/${family}/${weight}`,boundary({[name]:1}));}
  const modules = new Map();
  function load(specifier) {
    const name=specifier.replace(/^\.\//,'').replace(/\.tsx?$/,'');
    if(modules.has(name))return modules.get(name);
    const pending=(async()=>{let path=resolve(app,'src',name+'.ts');try{await access(path);}catch{path=resolve(app,'src',name+'.tsx');}
      const source=await readFile(path,'utf8');
      const code=ts.transpileModule(source+(name==='ui'?'\nexport { MessageMenu };':''),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,jsx:ts.JsxEmit.ReactJSX},fileName:path}).outputText;
      return new vm.SourceTextModule(code,{identifier:path});})();modules.set(name,pending);return pending;
  }
  const link=specifier=>ports.get(specifier)??load(specifier);
  const sheet=await load('sheet');await sheet.link(link);await sheet.evaluate();
  let Host=props=>props.children;
  try { await access(resolve(app,'src/activity-overlays.tsx'));const overlay=await load('activity-overlays');if(overlay.status==='unlinked')await overlay.link(link);await overlay.evaluate();Host=overlay.namespace.ActivityOverlayHost; } catch(error) { if(error.code!=='ENOENT')throw error; }
  async function namespace(name){const module=await load(name);if(module.status==='unlinked')await module.link(link);await module.evaluate();return module.namespace;}
  const overlay=await namespace('activity-overlays');
  return {...overlay,Sheet:sheet.namespace.Sheet,Host,animations,focused,scope:scoped.scope,revoke:scoped.revoke,
    SafeProvider:({children})=>React.createElement(Safe.Provider,{value:{top:24,bottom:44,left:0,right:0}},children),
    KeyboardProvider:({children})=>React.createElement(Keyboard.Provider,{value:'owned-keyboard'},children),
    ui:()=>namespace('ui'),extraWindows:()=>extraWindows,setPreviousInput(value){currentInput=value;}};
}
test('actual Android Sheet keeps a private form in the protected activity instead of creating an unowned native window',async()=>{
  const f=await fixture();let tree;
  try {
    await act(async()=>{tree=create(React.createElement(f.Host,{scope:f.scope},React.createElement(f.Sheet,{visible:true,label:'Owned form',onClose(){}},React.createElement('private-form'))));});
    assert.equal(f.extraWindows(),0,'a private activity overlay must not create RNModal/ComponentDialog');
    assert.equal(tree.root.findAllByType('private-form').length,1,'the private form must remain rendered in its activity');
  } finally {if(tree)await act(async()=>{tree.unmount();});}
});


const overlayLayers=tree=>tree.root.findAll(node=>node.type==='view'&&node.props.testID==='protected-activity-overlay');
const activityContent=tree=>tree.root.findAll(node=>node.type==='view'&&node.props.testID==='protected-activity-content')[0];
function capture(f,values){return function Capture(){const lease=f.useActivityOverlay();React.useLayoutEffect(()=>{if(lease)values.push(lease);},[lease]);return null;};}

test('topmost back consumes busy dismissal, stable updates preserve stack order, and background accessibility is hidden',async()=>{
  const f=await fixture(),leases=[];let tree,updateFirst,closeB=false;const closed=[];
  const Capture=capture(f,leases);
  function Scenario(){const [revision,setRevision]=React.useState(0),[a,setA]=React.useState(true),[b,setB]=React.useState(true);updateFirst=()=>setRevision(x=>x+1);
    return React.createElement(f.Host,{scope:f.scope},React.createElement(Capture),
      React.createElement(f.ActivityModal,{visible:a,onRequestClose(){closed.push('A');setA(false);}},React.createElement('form-a',{revision})),
      React.createElement(f.ActivityModal,{visible:b,onRequestClose(){closed.push('B');if(closeB)setB(false);}},React.createElement('form-b')));}
  try{
    await act(async()=>{tree=create(React.createElement(Scenario));});const lease=leases.at(-1);
    assert.equal(activityContent(tree).props.importantForAccessibility,'no-hide-descendants');
    await act(async()=>{updateFirst();});
    assert.equal(overlayLayers(tree).length,2);assert.equal(overlayLayers(tree)[0].props.accessibilityElementsHidden,true);assert.equal(overlayLayers(tree)[1].props.accessibilityElementsHidden,false);
    await act(async()=>{assert.equal(lease.dismissTop(),true);});assert.deepEqual(closed,['B']);assert.equal(tree.root.findAllByType('form-b').length,1);
    closeB=true;await act(async()=>{assert.equal(lease.dismissTop(),true);});assert.equal(tree.root.findAllByType('form-b').length,0);
    await act(async()=>{assert.equal(lease.dismissTop(),true);});assert.deepEqual(closed,['B','B','A']);
    assert.equal(activityContent(tree).props.importantForAccessibility,'auto');assert.equal(lease.dismissTop(),false);assert.equal(f.extraWindows(),0);
  }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

test('StrictMode and Activity effect replay never allow an old captured lease to insert into the successor generation',async()=>{
  const f=await fixture(),leases=[];const Capture=capture(f,leases);let tree;
  const render=mode=>React.createElement(React.StrictMode,null,React.createElement(React.Activity,{mode},React.createElement(f.Host,{scope:f.scope},React.createElement(Capture))));
  try{
    await act(async()=>{tree=create(render('visible'));});const old=leases.at(-1);assert.ok(old);
    const stale=()=>old.register(Symbol(),React.createElement('stale-private-content'),()=>{});
    await act(async()=>{tree.update(render('hidden'));});assert.equal(old.closed,true);
    await act(async()=>{tree.update(render('visible'));});const fresh=leases.at(-1);assert.notEqual(fresh,old);assert.equal(fresh.closed,false);
    const key=Symbol();await act(async()=>{fresh.register(key,React.createElement('fresh-private-content'),()=>{});stale();});
    assert.equal(tree.root.findAllByType('stale-private-content').length,0);assert.equal(tree.root.findAllByType('fresh-private-content').length,1);
    await act(async()=>{old.remove(key);});assert.equal(tree.root.findAllByType('fresh-private-content').length,1);
    await act(async()=>{f.scope.dispose();stale();fresh.register(Symbol(),React.createElement('after-dispose'),()=>{});});
    assert.equal(tree.root.findAllByType('fresh-private-content').length,0);assert.equal(tree.root.findAllByType('after-dispose').length,0);
  }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

test('actual Dialog/Field preserve show-time focus plus safe-area and keyboard context at the activity host',async()=>{
  const f=await fixture(),ui=await f.ui();let tree;
  try{
    await act(async()=>{tree=create(React.createElement(f.SafeProvider,null,React.createElement(f.KeyboardProvider,null,
      React.createElement(f.Host,{scope:f.scope},React.createElement(ui.Dialog,{visible:true,label:'Owned dialog',onClose(){}},
        React.createElement(ui.Field,{label:'Owned input',value:'',placeholder:'name',onChangeText(){},autoFocus:true}))))));});
    assert.equal(f.extraWindows(),0);assert.equal(f.focused.length,0,'autofocus must wait until the actual sheet reports shown');
    assert.equal(tree.root.findByType('text-input').props.autoFocus,false,'DialogShown must travel with the registered content');
    assert.equal(tree.root.findByType('keyboard-avoiding').props.keyboardContext,'owned-keyboard');assert.equal(tree.root.findByType('keyboard-avoiding').props.safeAreaBottom,44);
    const animation=f.animations.find(value=>value.options.useNativeDriver===true&&value.options.toValue===1);assert.ok(animation);
    await act(async()=>{animation.done?.({finished:true});});assert.deepEqual(f.focused,['Owned input']);
  }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

test('actual message menu converts window anchors into a nonzero activity-host origin',async()=>{
  const f=await fixture({origin:{x:20,y:40,width:720,height:900},window:{width:800,height:1000}}),ui=await f.ui();let tree;
  try{
    await act(async()=>{tree=create(React.createElement(f.Host,{scope:f.scope},React.createElement(ui.MessageMenu,{anchor:{x:100,y:500,width:80,height:32},sent:false,canReact:false,actions:[{icon:'copy',label:'Copy',onPress(){}}],onClose(){}})));});
    const menu=tree.root.findAll(node=>node.type==='animated-view'&&node.props.accessibilityLabel==='Message actions')[0];assert.ok(menu);
    const style=Object.assign({},...menu.props.style.filter(value=>value&&typeof value==='object'));
    assert.equal(style.left,80,'an unclamped menu must align with anchor.x minus the actual host origin');assert.ok(style.top<460&&style.top>=0);
    assert.equal(f.extraWindows(),0);
  }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

test('current close errors propagate unchanged and retiring a scope never restores old input focus',async()=>{
  const f=await fixture(),leases=[];const Capture=capture(f,leases);let tree;const defect=Error('close_defect');let restores=0;
  f.setPreviousInput({focus(){restores++;},blur(){}});
  try{
    await act(async()=>{tree=create(React.createElement(f.Host,{scope:f.scope},React.createElement(Capture),React.createElement(f.ActivityModal,{visible:true,onRequestClose(){throw defect;}},React.createElement('private-form'))));});
    assert.throws(()=>leases.at(-1).dismissTop(),error=>error===defect);
    await act(async()=>{f.scope.dispose();});assert.equal(restores,0);assert.equal(tree.root.findAllByType('private-form').length,0);
  }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

for(const platform of ['ios','web'])test(`${platform} retains the native/platform Modal boundary`,async()=>{
 const f=await fixture({platform});let tree;
 try{await act(async()=>{tree=create(React.createElement(f.Host,{scope:f.scope},React.createElement(f.ActivityModal,{visible:true,onRequestClose(){}},React.createElement('platform-form'))));});assert.equal(f.extraWindows(),1);assert.equal(tree.root.findAllByType('platform-form').length,1);}finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});


test('closing the final current overlay restores the captured input rather than a later global focus target',async()=>{
 const f=await fixture(),leases=[];const Capture=capture(f,leases);let tree,close,restored=0,wrong=0;
 f.setPreviousInput({focus(){restored++;},blur(){}});
 function Scenario(){const[visible,setVisible]=React.useState(true);close=()=>setVisible(false);return React.createElement(f.Host,{scope:f.scope},React.createElement(Capture),React.createElement(f.ActivityModal,{visible,onRequestClose:close},React.createElement('private-form')));}
 try{await act(async()=>{tree=create(React.createElement(Scenario));});f.setPreviousInput({focus(){wrong++;},blur(){}});await act(async()=>{leases.at(-1).dismissTop();});assert.equal(restored,1);assert.equal(wrong,0);assert.equal(tree.root.findAllByType('private-form').length,0);}finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

test('actual Sheet keeps pull-down and scrim dismissal with its existing exit animation',async()=>{
 const f=await fixture();let tree,closes=0;
 function Scenario(){const[visible,setVisible]=React.useState(true);return React.createElement(f.Host,{scope:f.scope},React.createElement(f.Sheet,{visible,label:'Owned gesture sheet',onClose(){closes++;setVisible(false);}},React.createElement('private-form')));}
 try{
  await act(async()=>{tree=create(React.createElement(Scenario));});
  const sheet=tree.root.findAll(node=>node.type==='animated-view'&&node.props.accessibilityLabel==='Owned gesture sheet')[0];assert.ok(sheet);
  await act(async()=>{sheet.props.onPanResponderRelease(null,{dy:1000,vy:0});});assert.equal(closes,1);assert.equal(tree.root.findAllByType('private-form').length,1,'exit animation retains the sheet before its completion');
  const exit=f.animations.filter(value=>value.options.useNativeDriver===true&&value.options.toValue===0).at(-1);assert.ok(exit);
  await act(async()=>{exit.done?.({finished:true});});assert.equal(tree.root.findAllByType('private-form').length,0);assert.equal(activityContent(tree).props.importantForAccessibility,'auto');
  await act(async()=>{tree.update(React.createElement(Scenario,{key:'fresh-sheet'}));});
  const scrim=tree.root.findAll(node=>node.type==='pressable'&&node.props.accessible===false&&node.props.importantForAccessibility==='no');assert.equal(scrim.length,1);
  await act(async()=>{scrim[0].props.onPress();});assert.equal(closes,2,'the actual scrim retains explicit dismissal');
  const scrimExit=f.animations.filter(value=>value.options.useNativeDriver===true&&value.options.toValue===0).at(-1);await act(async()=>{scrimExit.done?.({finished:true});});assert.equal(tree.root.findAllByType('private-form').length,0);
 }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});


test('opening and nesting activity overlays blur hidden inputs and restore only the current top owner',async()=>{
 const f=await fixture(),leases=[],events=[];const Capture=capture(f,leases);let tree;
 const input=name=>({focus(){events.push('focus-'+name);f.setPreviousInput(this);},blur(){events.push('blur-'+name);f.setPreviousInput(undefined);}});
 const main=input('main'),nested=input('A');f.setPreviousInput(main);
 try{
  await act(async()=>{tree=create(React.createElement(f.Host,{scope:f.scope},React.createElement(Capture)));});const lease=leases.at(-1),a=Symbol(),b=Symbol();
  await act(async()=>{lease.register(a,React.createElement('form-a'),()=>{});});
  assert.deepEqual(events,['blur-main'],'opening a no-input dialog must stop keyboard editing of the hidden activity');
  assert.equal(activityContent(tree).props.pointerEvents,'none','the hidden activity must reject touches as well as accessibility');
  f.setPreviousInput(nested);await act(async()=>{lease.register(b,React.createElement('form-b'),()=>{});});
  assert.deepEqual(events,['blur-main','blur-A'],'a nested no-input dialog must blur the previous overlay field');
  assert.equal(overlayLayers(tree)[0].props.pointerEvents,'none');assert.equal(overlayLayers(tree)[1].props.pointerEvents,'auto');
  await act(async()=>{lease.remove(b);});assert.deepEqual(events,['blur-main','blur-A','focus-A']);assert.equal(activityContent(tree).props.pointerEvents,'none');
  await act(async()=>{lease.remove(a);});assert.deepEqual(events,['blur-main','blur-A','focus-A','focus-main']);assert.equal(activityContent(tree).props.pointerEvents,'auto');
 }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});

test('reentrant scope disposal while blurring cannot publish a new overlay or restore retired focus',async()=>{
 const f=await fixture(),leases=[];const Capture=capture(f,leases);let tree,restores=0;
 f.setPreviousInput({focus(){restores++;},blur(){f.scope.dispose();}});
 try{
  await act(async()=>{tree=create(React.createElement(f.Host,{scope:f.scope},React.createElement(Capture)));});const lease=leases.at(-1);
  await act(async()=>{lease.register(Symbol(),React.createElement('late-private-form'),()=>{});});
  assert.equal(lease.closed,true);assert.equal(tree.root.findAllByType('late-private-form').length,0);assert.equal(restores,0);
 }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});


test('an underlying Dialog Field cannot take delayed focus through a newer overlay',async()=>{
 const f=await fixture(),ui=await f.ui();let tree,openTop,closeTop;
 function Scenario(){const[top,setTop]=React.useState(false);openTop=()=>setTop(true);closeTop=()=>setTop(false);
  return React.createElement(f.Host,{scope:f.scope},React.createElement(ui.Dialog,{visible:true,label:'First',onClose(){}},React.createElement(ui.Field,{label:'Underlying input',value:'',placeholder:'name',onChangeText(){},autoFocus:true})),React.createElement(f.ActivityModal,{visible:top,onRequestClose:closeTop},React.createElement('top-confirmation')));}
 try{
  await act(async()=>{tree=create(React.createElement(Scenario));});assert.equal(f.focused.length,0);
  await act(async()=>{openTop();});const enter=f.animations.find(value=>value.options.useNativeDriver===true&&value.options.toValue===1);assert.ok(enter);
  await act(async()=>{enter.done?.({finished:true});});assert.equal(f.focused.length,0,'a lower sheet finishing its animation must not focus behind the top confirmation');
  await act(async()=>{closeTop();});assert.deepEqual(f.focused,['Underlying input'],'the still-current lower field may focus after the top overlay closes');
 }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});


test('replacing a focused Sheet with a confirmation in one commit restores the live underlay, never the retired field',async()=>{
 const f=await fixture(),ui=await f.ui();let tree,hideSheet,showConfirmation,closeConfirmation,restores=0;
 f.setPreviousInput({focus(){restores++;f.setPreviousInput(this);},blur(){f.setPreviousInput(undefined);}});
 function Scenario(){const[sheet,setSheet]=React.useState(true),[confirm,setConfirm]=React.useState(false);hideSheet=()=>setSheet(false);showConfirmation=()=>setConfirm(true);closeConfirmation=()=>setConfirm(false);
  return React.createElement(f.Host,{scope:f.scope},React.createElement(ui.Dialog,{visible:sheet,label:'Retiring sheet',onClose:hideSheet},React.createElement(ui.Field,{label:'Retiring input',value:'',placeholder:'name',onChangeText(){},autoFocus:true})),React.createElement(f.ActivityModal,{visible:confirm,onRequestClose:closeConfirmation},React.createElement('replacement-confirmation')));}
 try{
  await act(async()=>{tree=create(React.createElement(Scenario));});
  const enter=f.animations.find(value=>value.options.useNativeDriver===true&&value.options.toValue===1);assert.ok(enter);
  await act(async()=>{enter.done?.({finished:true});});assert.deepEqual(f.focused,['Retiring input']);
  await act(async()=>{hideSheet();});const exit=f.animations.filter(value=>value.options.useNativeDriver===true&&value.options.toValue===0).at(-1);assert.ok(exit);
  await act(async()=>{exit.done?.({finished:true});showConfirmation();});
  assert.equal(tree.root.findAllByType('text-input').length,0);assert.equal(tree.root.findAllByType('replacement-confirmation').length,1);assert.equal(restores,0,'opening a replacement must not focus the hidden underlay');
  await act(async()=>{closeConfirmation();});
  assert.equal(restores,1,'closing the replacement must restore the still-live underlay captured before the sheet');
  assert.deepEqual(f.focused,['Retiring input'],'a retired sheet input must never regain focus');
 }finally{if(tree)await act(async()=>{tree.unmount();});f.scope.dispose();}
});
