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

import BaseContext from './BaseContext.ets'
import ApplicationContext from './ApplicationContext.ets'
// import EventHub from '../../../js/napi/app/event_hub/event_hub.sts';
// import ApplicationInfo from 'bms/ApplicationInfo'

export abstract class Context implements BaseContext{
    area: int = 0;
    filesDir: string = "";
    tempDir: string = "";
    // applicationInfo?: ApplicationInfo;
    // eventHub: EventHub = new EventHub();

    private applicationContext?: ApplicationContext;

    getApplicationContext():ApplicationContext | undefined {
        console.log("ywz getApplicationContext 111");
        return this.applicationContext;
    }
}