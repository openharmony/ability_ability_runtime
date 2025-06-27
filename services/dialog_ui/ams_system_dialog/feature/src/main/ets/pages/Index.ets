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

import { IntentContent, IntentInfo } from '../view/IntentContent'
import { IntentDetailPage } from '../view/IntentDetailPage'

@Entry
@Component
struct Index {
  @Provide('articlePathStack') articlePathStack: NavPathStack = new NavPathStack();
  scroller: Scroller = new Scroller();

  @Builder
  intentRouter(name: string, param?: IntentInfo) {
    if (name === 'intentDetail') {
      IntentDetailPage()
    }else {
      IntentContent()
    }
  }

  build() {
      Navigation(this.articlePathStack) {
        IntentContent()
      }
      .navDestination(this.intentRouter)
      .hideTitleBar(true)
      .mode(NavigationMode.Stack)
  }
}