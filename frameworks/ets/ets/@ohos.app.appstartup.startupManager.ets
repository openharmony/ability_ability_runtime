/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import StartupConfig from './@ohos.app.appstartup.StartupConfig';
import common from '@ohos.app.ability.common';
import { BusinessError, AsyncCallback } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace startupManager {
    loadLibraryWithPermissionCheck("startup_manager_ani_kit.z", "@ohos.app.appstartup.startupManager");

    export native function nativeRun(startupTasks: Array<string>, callback: AsyncCallbackWrapper<void>,
        config?: StartupConfig, context?: common.AbilityStageContext): void;

    export native function nativeRemoveAllStartupTaskResults(): void;

    export native function nativeGetStartupTaskResult(startupTask: string): Any;

    export native function nativeIsStartupTaskInitialized(startupTask: string): boolean;

    export native function nativeRemoveStartupTaskResult(startupTask: string): void;

    export function run(startupTasks: Array<string>, config?: StartupConfig): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null, data: undefined)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                console.log('ready to call nativeRun');
                startupManager.nativeRun(startupTasks, myCall, config, undefined);
            });
        });
        return p;
    }

    export function run(startupTasks: Array<string>, context: common.AbilityStageContext,
        config: StartupConfig): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null, data: undefined)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                console.log('ready to call nativeRun');
                startupManager.nativeRun(startupTasks, myCall, config, context);
            });
        });
        return p;
    }

    export function removeAllStartupTaskResults(): void {
        try {
            startupManager.nativeRemoveAllStartupTaskResults();
        } catch (err) {
            throw(err);
        }
    }

    export function getStartupTaskResult(startupTask: string): Any {
        try {
            return startupManager.nativeGetStartupTaskResult(startupTask);
        } catch (err) {
            throw(err);
        }
    }

    export function isStartupTaskInitialized(startupTask: string): boolean {
        try {
            return startupManager.nativeIsStartupTaskInitialized(startupTask);
        } catch (err) {
            throw(err);
        }
    }

    export function removeStartupTaskResult(startupTask: string): void {
        try {
            startupManager.nativeRemoveStartupTaskResult(startupTask);
        } catch (err) {
            throw(err);
        }
    }
}