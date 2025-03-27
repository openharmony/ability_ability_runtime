/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//import AbilityMonitor from 'AbilityMonitor';
import Want from '@ohos.app.ability.Want';
import { Context } from './application/Context';
import { BusinessError, AsyncCallback } from '@ohos.base';

export class AbilityMonitor {

    abilityName: string= "";
    moduleName: string= "";
}

export default interface AbilityDelegator {
    printSync(msg: string): void;
    getAppContext(): Context;
    finishTest(msg: string, code: number, callback: AsyncCallback<void>):void;
    finishTest(msg: string, code: number):Promise<void>;
    executeShellCommand (cmd: String, callback: AsyncCallback<ShellCmdResult>) : void;
    executeShellCommand (cmd: String, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult>) : void;
    executeShellCommand (cmd: string, timeoutSecs?: number) : Promise<ShellCmdResult>;
    addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void
    addAbilityMonitor(monitor: AbilityMonitor): Promise<void>;
    addAbilityMonitorAsync(monitor: AbilityMonitor): void;
    startAbility(want: Want, callback: AsyncCallback<void>): void;
    startAbility(want: Want): Promise<void>;
    // other api
}

class ShellCmdResult {
  stdResult: string = "";
  exitCode: int;
}

class AbilityDelegatorInner implements AbilityDelegator {
    public native printSync(msg: string): void;
    public native finishTestSync(msg: String, code: number): int;
    public native executeShellCommandsync(cmd: string, timeoutSecs: number): ShellCmdResult;
    public native getAppContext(): Context;
    public native addAbilityMonitorAsync(monitor: AbilityMonitor): void;
    public native startAbilityAsync(want: Want) : int;
    // other api

    finishTest(msg: string, code: number, callback: AsyncCallback<void>):void{
        console.log("finishTest callback1_test start");
        let p1 = taskpool.execute(():undefined => {this.finishTestSync(msg, code);  return undefined});
            p1.then((e :NullishType)=>{
                let resultCode: Int  = e as Int;
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }, (err:Object): void => {
            });
    }
    finishTest(msg: string, code: number):Promise<void>{
        console.log("finishTest promise1_test start");
        let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute(():undefined => {this.finishTestSync(msg, code);  return undefined});
            p1.then((e :NullishType)=>{
            let PromiseLike = e as PromiseLike<void>;
            resolve(PromiseLike);
            }, (err:Object): void => {
            });
        });
        return p;
    }

    executeShellCommand (cmd: String, callback: AsyncCallback<ShellCmdResult>) : void {
        console.log("executeShellCommand callback2_01");
        let timeoutSecs =  0;
        let pCallback1 = taskpool.execute(():ShellCmdResult => {return this.executeShellCommandsync(cmd, timeoutSecs)});
        console.log("executeShellCommand callback2_04");
        pCallback1.then((e :NullishType)=>{
        let data = e as ShellCmdResult;
        let resultCode: Int  = 0;
        let error: BusinessError = { code: resultCode.intValue(), data: undefined };
        callback(error, data);
        console.log("executeShellCommand callback2_06");
        }, (err: Object) : void => {
        console.log("executeShellCommand callback2_0606 err end");
        });
    }
    executeShellCommand (cmd: String, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult>) : void {
        console.log("executeShellCommand callback1_01");
        let pCallback2 = taskpool.execute(():ShellCmdResult => {return this.executeShellCommandsync(cmd, timeoutSecs)});
        console.log("executeShellCommand callback1_04");
        pCallback2.then((e :NullishType)=>{
        let data = e as ShellCmdResult;
        let resultCode: Int  = 0;
        let error: BusinessError = { code: resultCode.intValue(), data: undefined };
        callback(error, data);
        console.log("executeShellCommand callback1_06");
        }, (err: Object) : void => {
        console.log("executeShellCommand callback1_0606 err end");
        });
    }
    executeShellCommand (cmd: string, timeoutSecs?: number) : Promise<ShellCmdResult>{
        if (timeoutSecs == null) {
        let pPromise2 = new Promise<ShellCmdResult>((resolve: (v: ShellCmdResult) => void, reject: (error: Object) => void) => {
            console.log("executeShellCommand promise1_01");
            let pPromise1 = taskpool.execute(():ShellCmdResult => {return this.executeShellCommandsync(cmd, 0);});
            pPromise1.then((e :NullishType)=>{
            console.log("executeShellCommand promise1_04");
            let r : ShellCmdResult =  e as ShellCmdResult;
            resolve(r);
            }, ( error: Object) : void => {
            console.log("executeShellCommandSync promise1 end");
            });
        });
        return pPromise2;
        } else {
        let pPromise = new Promise<ShellCmdResult>((resolve: (v: ShellCmdResult) => void, reject: (error: Object) => void) => {
            console.log("executeShellCommand promise1_01");
            let pPromise1 = taskpool.execute(():ShellCmdResult=> {return  this.executeShellCommandsync(cmd, timeoutSecs as double)});
            pPromise1.then((e :NullishType)=>{
            console.log("executeShellCommand promise1_04");
            let r : ShellCmdResult =  e as ShellCmdResult;
            resolve(r);
            }, ( error: Object) : void => {
            console.log("executeShellCommandSync promise1 end");
            });
        });
        return pPromise;
        }
    }

    addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void {
        let p1 = taskpool.execute(():undefined => {this.addAbilityMonitorAsync(monitor);  return undefined});
            p1.then((e :NullishType)=>{
                let resultCode: Int  = e as Int;
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }, (err:Object): void => {
            });

    }
    addAbilityMonitor(monitor: AbilityMonitor): Promise<void> {
        let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute(():undefined => {this.addAbilityMonitorAsync(monitor);  return undefined});
            p1.then((e :NullishType)=>{
            let PromiseLike = e as PromiseLike<void>;
            resolve(PromiseLike);
            }, (err:Object): void => {
            });
        });
        return p;
    }

    startAbility(want: Want, callback: AsyncCallback<void>): void {
        let p1 = taskpool.execute(():undefined => {this.startAbilityAsync(want);  return undefined});
            p1.then((e :NullishType)=>{
                let resultCode: Int  = e as Int;
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }, (err:Object): void => {
            });

    }
    startAbility(want: Want): Promise<void> {
        let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute(():undefined => {this.startAbilityAsync(want);  return undefined});
            p1.then((e :NullishType)=>{
            let PromiseLike = e as PromiseLike<void>;
            resolve(PromiseLike);
            }, (err:Object): void => {
            });
        });
        return p;
    }
}
