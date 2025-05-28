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

import { AbilityMonitor } from 'application.AbilityMonitor';
import Want from '@ohos.app.ability.Want';
import Context from 'application.Context';
import { BusinessError, AsyncCallback } from '@ohos.base';
import { ShellCmdResult } from 'application.shellCmdResult';
import UIAbility from '@ohos.app.ability.UIAbility';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import AbilityStageMonitor from './AbilityStageMonitor';
import AbilityStage from '@ohos.app.ability.AbilityStage';

export interface AbilityDelegator {
  printSync(msg: string): void;

  getAppContext(): Context;

  finishTest(msg: string, code: number, callback: AsyncCallback<void>): void;

  finishTest(msg: string, code: number): Promise<void>;

  executeShellCommand(cmd: String, callback: AsyncCallback<ShellCmdResult>): void;

  executeShellCommand(cmd: String, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult>): void;

  executeShellCommand(cmd: string, timeoutSecs?: number): Promise<ShellCmdResult>;

  addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void;
  addAbilityMonitor(monitor: AbilityMonitor): Promise<void>;

  addAbilityMonitorSync(monitor: AbilityMonitor): void;

  removeAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void
  removeAbilityMonitor(monitor: AbilityMonitor): Promise<void>;

  removeAbilityMonitorSync(monitor: AbilityMonitor): void;

  waitAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<UIAbility>): void;
  waitAbilityMonitor(monitor: AbilityMonitor, timeout: number, callback: AsyncCallback<UIAbility>): void;
  waitAbilityMonitor(monitor: AbilityMonitor, timeout?: number): Promise<UIAbility>;

  addAbilityStageMonitor(monitor: AbilityStageMonitor, callback: AsyncCallback<void>): void;
  addAbilityStageMonitor(monitor: AbilityStageMonitor): Promise<void>;

  addAbilityStageMonitorSync(monitor: AbilityStageMonitor): void;

  removeAbilityStageMonitor(monitor: AbilityStageMonitor, callback: AsyncCallback<void>): void;
  removeAbilityStageMonitor(monitor: AbilityStageMonitor): Promise<void>;

  removeAbilityStageMonitorSync(monitor: AbilityStageMonitor): void;

  waitAbilityStageMonitor(monitor: AbilityStageMonitor, callback: AsyncCallback<AbilityStage>): void;
  waitAbilityStageMonitor(monitor: AbilityStageMonitor, timeout: number, callback: AsyncCallback<AbilityStage>): void;
  waitAbilityStageMonitor(monitor: AbilityStageMonitor, timeout?: number): Promise<AbilityStage>;

  doAbilityForeground(ability: UIAbility, callback: AsyncCallback<void>): void;
  doAbilityForeground(ability: UIAbility): Promise<void>;

  doAbilityBackground(ability: UIAbility, callback: AsyncCallback<void>): void;
  doAbilityBackground(ability: UIAbility): Promise<void>;

  print(msg: string, callback: AsyncCallback<void>): void;
  print(msg: string): Promise<void>;

  getAbilityState(ability: UIAbility): number;

  setMockList(mockList: Record<string, string>): void;

  startAbility(want: Want, callback: AsyncCallback<void>): void;
  startAbility(want: Want): Promise<void>;

  getCurrentTopAbility(callback: AsyncCallback<UIAbility>);
  getCurrentTopAbility(): Promise<UIAbility>;
}

class AbilityDelegatorInner implements AbilityDelegator {
  public native nativeGetCurrentTopAbility(): UIAbility;

  public native printSync(msg: string): void;

  public native getAppContext(): Context;

  public native nativeFinishTest(msg: String, code: number, callback: AsyncCallbackWrapper<void>): void;

  public native nativeExecuteShellCommand(cmd: string, timeoutSecs: number,
    callback: AsyncCallbackWrapper<ShellCmdResult>): void;

  public native nativeAddAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallbackWrapper<void>): void;
  public native addAbilityMonitorSync(monitor: AbilityMonitor): void;

  public native removeAbilityMonitorAsync(monitor: AbilityMonitor, callback: AsyncCallbackWrapper<void>): void;
  public native removeAbilityMonitorSync(monitor: AbilityMonitor): void;

  public native waitAbilityMonitorAsync(monitor: AbilityMonitor, timeout: number,
    callback: AsyncCallbackWrapper<UIAbility>): void;

  public native addAbilityStageMonitorAsync(monitor: AbilityStageMonitor, callback: AsyncCallbackWrapper<void>): void;
  public native addAbilityStageMonitorSync(monitor: AbilityStageMonitor): void;

  public native removeAbilityStageMonitorAsync(monitor: AbilityStageMonitor, callback: AsyncCallbackWrapper<void>): void;
  public native removeAbilityStageMonitorSync(monitor: AbilityStageMonitor): void;

  public native waitAbilityStageMonitorAsync(monitor: AbilityStageMonitor, timeout: number,
    callback: AsyncCallbackWrapper<AbilityStage>): void;

  public native doAbilityForegroundAsync(ability: UIAbility, callback: AsyncCallbackWrapper<void>): void;

  public native doAbilityBackgroundAsync(ability: UIAbility, callback: AsyncCallbackWrapper<void>): void;

  public native printAsync(msg: string, callback: AsyncCallbackWrapper<void>): void;

  public native setMockList(mockList: Record<string, string>): void;

  public native getAbilityState(ability: UIAbility): number;

  public native nativeStartAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;

  finishTest(msg: string, code: number, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeFinishTest(msg, code, myCall);
    });
  }
  finishTest(msg: string, code: number): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeFinishTest(msg, code, myCall);
        });
      });
    return p;
  }

  executeShellCommand(cmd: string, callback: AsyncCallback<ShellCmdResult, void>): void {
    let timeoutSecs = 0;
    let myCall = new AsyncCallbackWrapper<ShellCmdResult>(callback);
    taskpool.execute((): void => {
      this.nativeExecuteShellCommand(cmd, timeoutSecs, myCall);
    });
  }
  executeShellCommand(cmd: string, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult, void>): void {
    let myCall = new AsyncCallbackWrapper<ShellCmdResult>(callback);
    taskpool.execute((): void => {
      this.nativeExecuteShellCommand(cmd, timeoutSecs, myCall);
    });
  }
  executeShellCommand(cmd: string, timeoutSecs?: number): Promise<ShellCmdResult> {
    let p = new Promise<ShellCmdResult>((resolve: (data: ShellCmdResult) => void,
      reject: (err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<ShellCmdResult>((err: BusinessError<void>, data: ShellCmdResult) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        if (timeoutSecs == null) {
          this.nativeExecuteShellCommand(cmd, 0, myCall);
        } else {
          this.nativeExecuteShellCommand(cmd, timeoutSecs as double, myCall);
        }
      });
    });
    return p;
  }

  addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeAddAbilityMonitor(monitor, myCall);
    });
  }
  addAbilityMonitor(monitor: AbilityMonitor): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeAddAbilityMonitor(monitor, myCall);
        });
      });
    return p;
  }

  removeAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.removeAbilityMonitorAsync(monitor, myCall);
    });
  }
  removeAbilityMonitor(monitor: AbilityMonitor): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.removeAbilityMonitorAsync(monitor, myCall);
        });
      });
    return p;
  }

  waitAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<UIAbility, void>): void {
    let timeout = -1;
    let myCall = new AsyncCallbackWrapper<UIAbility>(callback);
    taskpool.execute((): void => {
      this.waitAbilityMonitorAsync(monitor, timeout, myCall);
    });
  }
  waitAbilityMonitor(monitor: AbilityMonitor, timeout: number, callback: AsyncCallback<UIAbility, void>): void {
    let myCall = new AsyncCallbackWrapper<UIAbility>(callback);
    taskpool.execute((): void => {
      this.waitAbilityMonitorAsync(monitor, timeout, myCall);
    });
  }
  waitAbilityMonitor(monitor: AbilityMonitor, timeout?: number): Promise<UIAbility> {
    let p = new Promise<UIAbility>((resolve: (data: UIAbility) => void,
      reject: (err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<UIAbility>((err: BusinessError<void>, data: UIAbility) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        if (timeout == null) {
          this.waitAbilityMonitorAsync(monitor, -1, myCall);
        } else {
          this.waitAbilityMonitorAsync(monitor, timeout as double, myCall);
        }
      });
    });
    return p;
  }

  addAbilityStageMonitor(monitor: AbilityStageMonitor, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.addAbilityStageMonitorAsync(monitor, myCall);
    });
  }
  addAbilityStageMonitor(monitor: AbilityStageMonitor): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.addAbilityStageMonitorAsync(monitor, myCall);
        });
      });
    return p;
  }

  removeAbilityStageMonitor(monitor: AbilityStageMonitor, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.removeAbilityStageMonitorAsync(monitor, myCall);
    });
  }
  removeAbilityStageMonitor(monitor: AbilityStageMonitor): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.removeAbilityStageMonitorAsync(monitor, myCall);
        });
      });
    return p;
  }

 waitAbilityStageMonitor(monitor: AbilityStageMonitor, callback: AsyncCallback<AbilityStage, void>): void {
    let timeout = -1;
    let myCall = new AsyncCallbackWrapper<AbilityStage>(callback);
    taskpool.execute((): void => {
      this.waitAbilityStageMonitorAsync(monitor, timeout, myCall);
    });
  }
  waitAbilityStageMonitor(monitor: AbilityStageMonitor, timeout: number, callback: AsyncCallback<AbilityStage, void>): void {
    let myCall = new AsyncCallbackWrapper<AbilityStage>(callback);
    taskpool.execute((): void => {
      this.waitAbilityStageMonitorAsync(monitor, timeout, myCall);
    });
  }
  waitAbilityStageMonitor(monitor: AbilityStageMonitor, timeout?: number): Promise<AbilityStage> {
    let p = new Promise<AbilityStage>((resolve: (data: AbilityStage) => void,
      reject: (err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<AbilityStage>((err: BusinessError<void>, data: AbilityStage) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        if (timeout == null) {
          this.waitAbilityStageMonitorAsync(monitor, -1, myCall);
        } else {
          this.waitAbilityStageMonitorAsync(monitor, timeout as double, myCall);
        }
      });
    });
    return p;
  }

  doAbilityForeground(ability: UIAbility, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.doAbilityForegroundAsync(ability, myCall);
    });
  }
  doAbilityForeground(ability: UIAbility): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.doAbilityForegroundAsync(ability, myCall);
        });
      });
    return p;
  }

  doAbilityBackground(ability: UIAbility, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.doAbilityBackgroundAsync(ability, myCall);
    });
  }
  doAbilityBackground(ability: UIAbility): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.doAbilityBackgroundAsync(ability, myCall);
        });
      });
    return p;
  }

  print(msg: string, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.printAsync(msg, myCall);
    });
  }
  print(msg: string): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.printAsync(msg, myCall);
        });
      });
    return p;
  }

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbility(want, myCall);
    });
  }
  startAbility(want: Want): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeStartAbility(want, myCall);
        });
      });
    return p;
  }

  getCurrentTopAbility(callback: AsyncCallback<UIAbility>): void {
    let p = taskpool.execute((): UIAbility => {
      return this.nativeGetCurrentTopAbility()
    });
    console.log("getCurrentTopAbility callback2_04");
    p.then((e: NullishType) => {
      let ability = e as UIAbility;
      let resultCode: Int = 0;
      let error: BusinessError = { code: resultCode, data: undefined };
      callback(error, ability);
      console.log("getCurrentTopAbility callback2_06");
    }).catch((err: Error): void => {
      console.log("getCurrentTopAbility callback2_0606 err end");
      callback(err as BusinessError, {});
    });
  }
  getCurrentTopAbility(): Promise<UIAbility> {
    let p: Promise<UIAbility>  = new Promise<UIAbility>((resolve: (v: UIAbility) => void, reject: (error: Error) => void) => {
      console.log("getCurrentTopAbility promise1_01");
      let pPromise1 = taskpool.execute((): UIAbility => {
        return this.nativeGetCurrentTopAbility();
      });
      pPromise1.then((e: NullishType) => {
        console.log("getCurrentTopAbility promise1_04");
        let r: UIAbility = e as UIAbility;
        resolve(r);
      }).catch((err: Error): void => {
        reject(err);
        console.log("getCurrentTopAbility promise1 end");
      });
    });
    return p;
  }
}
