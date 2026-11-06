#!/usr/bin/env python3
"""Exercise FIFO completion ordering with the production Swift/Kotlin OS queues."""
from pathlib import Path
import subprocess,os
PRODUCT=Path(__file__).resolve().parents[1]
MODULE=PRODUCT/'apps/mobile/modules/mesh-messenger'
import tempfile
work=tempfile.TemporaryDirectory(prefix='morse-push-queue-')
w=Path(work.name)
subprocess.run(['xcrun','swiftc',str(MODULE/'ios/MeshMessengerPushSerialQueue.swift'),str(MODULE/'ios/push-proof/PushSerialProof.swift'),'-o',str(w/'swift-proof')],check=True)
subprocess.run([str(w/'swift-proof')],check=True)
c=Path.home()/'.gradle/caches/modules-2/files-2.1';java='/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home/bin/java'
def jar(group,name,version):
 found=list((c/group/name/version).glob('*/*.jar'));assert len(found)==1;return found[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.2.0');annotations=jar('org.jetbrains','annotations','13.0')
jars=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.2.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.2.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.kotlin','kotlin-daemon-embeddable','2.2.0'),jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.0'),annotations]
subprocess.run([java,'-cp',os.pathsep.join(map(str,jars)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',os.pathsep.join(map(str,[stdlib,annotations])),str(MODULE/'android/src/main/java/expo/modules/meshmessenger/MeshMessengerPushSerialQueue.kt'),str(MODULE/'android/push-proof/PushSerialProof.kt'),'-d',str(w/'proof.jar')],check=True)
subprocess.run([java,'-cp',os.pathsep.join(map(str,[w/'proof.jar',stdlib])),'expo.modules.meshmessenger.PushSerialProofKt'],check=True)

work.cleanup()
