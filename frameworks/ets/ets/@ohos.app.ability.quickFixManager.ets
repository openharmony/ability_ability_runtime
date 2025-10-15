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

import { BusinessError, AsyncCallback } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace quickFixManager {
    loadLibrary("quick_fix_manager_ani_kit.z");

export interface HapModuleQuickFixInfo {
    readonly moduleName: string;
    readonly originHapHash: string;
    readonly quickFixFilePath: string;
}
export class HapModuleQuickFixInfoImpl implements HapModuleQuickFixInfo {
    readonly moduleName: string = '';
    readonly originHapHash: string = '';
    readonly quickFixFilePath: string = '';
}

export interface ApplicationQuickFixInfo {
    readonly bundleName: string;
    readonly bundleVersionCode: long;
    readonly bundleVersionName: string;
    readonly quickFixVersionCode: long;
    readonly quickFixVersionName: string;
    readonly hapModuleQuickFixInfo: Array<HapModuleQuickFixInfo>;
}
export class ApplicationQuickFixInfoImpl implements ApplicationQuickFixInfo {
    readonly bundleName: string = '';
    readonly bundleVersionCode: long;
    readonly bundleVersionName: string = '';
    readonly quickFixVersionCode: long;
    readonly quickFixVersionName: string = '';
    readonly hapModuleQuickFixInfo: Array<HapModuleQuickFixInfo> = new Array<HapModuleQuickFixInfo>();
}

    export native function applyQuickFixSync(aniHapModuleQuickFixFiles: Array<string>,
        callback: AsyncCallbackWrapper<void>): void;
    export native function revokeQuickFixSync(aniBundleName: string,
        callback: AsyncCallbackWrapper<void>): void;
    export native function getApplicationQuickFixInfoSync(aniBundleName: string,
        callback: AsyncCallbackWrapper<ApplicationQuickFixInfo>): void;

    export function applyQuickFix(hapModuleQuickFixFiles: Array<string>): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
                if (err == null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                quickFixManager.applyQuickFixSync(hapModuleQuickFixFiles, myCall);
            });
        });
        return p;
    }

    export function applyQuickFix(hapModuleQuickFixFiles: Array<string>, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            quickFixManager.applyQuickFixSync(hapModuleQuickFixFiles, myCall);
        });
    }

    export function revokeQuickFix(bundleName: string): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
                if (err == null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                quickFixManager.revokeQuickFixSync(bundleName, myCall);
            });
        });
        return p;
    }

    export function revokeQuickFix(bundleName: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            quickFixManager.revokeQuickFixSync(bundleName, myCall);
        });
    }

    export function getApplicationQuickFixInfo(bundleName: string): Promise<ApplicationQuickFixInfo> {
        let p = new Promise<ApplicationQuickFixInfo>((resolve: (data: ApplicationQuickFixInfo) => void, 
        reject: (err: BusinessError) => void): void => {
            let myCall = new AsyncCallbackWrapper<ApplicationQuickFixInfo>((err: BusinessError | null, 
            data: ApplicationQuickFixInfo | undefined) => {
                if (err == null || err.code == 0) {
                    resolve(data as ApplicationQuickFixInfo);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                quickFixManager.getApplicationQuickFixInfoSync(bundleName, myCall);
            });
        });
        return p;
    }

    export function getApplicationQuickFixInfo(bundleName: string, callback: AsyncCallback<ApplicationQuickFixInfo>): void {
        let myCall = new AsyncCallbackWrapper<ApplicationQuickFixInfo>(callback);
        taskpool.execute((): void => {
            quickFixManager.getApplicationQuickFixInfoSync(bundleName, myCall);
        });
    }

}