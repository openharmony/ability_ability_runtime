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
interface BaseContext {
    readonly area: int;
    readonly filesDir: string;
    readonly tempDir: string;
}

abstract class Context implements BaseContext{
    area: int = 0;
    filesDir: string = "";
    tempDir: string = "";
}

class ApplicationContext extends Context {
}

class AbilityStage {}
class Want {}
type Callback<T> = (data: T)=> void;
class Result<T, E>{
  result:T;
  error:E;
  constructor(result: T , error: E) {
      this.result = result;
      this.error = error;
  }
}
type AsyncCallback<T> = (err: BusinessError<T>, data: T)=> void;

export default interface AbilityDelegator {
    printSync(msg: string): void;
    getAppContext(): Context;
    finishTest(msg: string, code: int, callback: AsyncCallback<void>):void;
    finishTest(msg: string, code: int):Promise<void>;
    executeShellCommand (cmd: String, callback: AsyncCallback<ShellCmdResult>) : void;
    executeShellCommand (cmd: String, timeoutSecs: int, callback: AsyncCallback<ShellCmdResult>) : void;
    executeShellCommand (cmd: string, timeoutSecs?: int) : Promise<ShellCmdResult>;
    // other api
}

class ShellCmdResult {
  stdResult: string = "";
  exitCode: int;
}

export class BusinessError<T = void> {
    code: number;
    data: T;
}

class AbilityDelegatorInner implements AbilityDelegator {
    public native printSync(msg: string): void;
    public native finishTestSync(a: String, b: int): int;
    public native executeShellCommandsync(cmd: string, timeoutSecs: int): ShellCmdResult;
    public native getAppContext(): Context;
    // other api

    finishTest(msg: string, code: int, callback: AsyncCallback<void>):void{
        let p1 = launch this.finishTestSync(msg, code);
            p1.then((e :NullishType)=>{
                let resultCode: Int  = e as Int;
                let r: BusinessError = { code: resultCode.intValue(), data: undefined };
                callback(r, undefined);
            }, (err:Object): void => {
            });
    }
    finishTest(msg: string, code: int):Promise<void>{
        let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Object) => void) => {
            let p1 = launch this.finishTestSync(msg, code);
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
        let pCallback1 = launch this.executeShellCommandsync(cmd, timeoutSecs);
        console.log("executeShellCommand callback2_04");
        pCallback1.then((e :NullishType)=>{
        let err = new BusinessError<ShellCmdResult>;
        let data  = new  ShellCmdResult;
        callback(err, data);
        console.log("executeShellCommand callback2_06");
        }, (err: Object) : void => {
        console.log("executeShellCommand callback2_0606 err end");
        });
    }
    executeShellCommand (cmd: String, timeoutSecs: int, callback: AsyncCallback<ShellCmdResult>) : void {
        console.log("executeShellCommand callback1_01");
        let pCallback2 = launch this.executeShellCommandsync(cmd, timeoutSecs);
        console.log("executeShellCommand callback1_04");
        pCallback2.then((e :NullishType)=>{
        let err = new BusinessError<ShellCmdResult>;
        let data  = new  ShellCmdResult;
        callback(err, data);
        console.log("executeShellCommand callback1_06");
        }, (err: Object) : void => {
        console.log("executeShellCommand callback1_0606 err end");
        });
    }
    executeShellCommand (cmd: string, timeoutSecs?: int) : Promise<ShellCmdResult>{
        if (timeoutSecs == null) {
        let pPromise2 = new Promise<ShellCmdResult>((resolve: (v: ShellCmdResult) => void, reject: (error: Object) => void) => {
            console.log("executeShellCommand promise1_01");
            let pPromise1 = launch this.executeShellCommandsync(cmd, 0);
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
            let pPromise1 = launch this.executeShellCommandsync(cmd, timeoutSecs as int);
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
}
