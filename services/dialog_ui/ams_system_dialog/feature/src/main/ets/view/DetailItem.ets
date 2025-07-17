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
import { IntentInfo } from './IntentContent';

@Component
export struct DetailItem {
  @Prop intentDetail: IntentInfo | null = null;

  build() {
    Column() {
      Text($r('app.string.Detail_subtitle_ytxx'))
        .fontFamily('HarmonyHeiTi-Medium')
        .fontSize(14)
        .fontWeight(500)
        .fontColor($r('app.color.font_color_06'))
        .textAlign(TextAlign.Start)
        .lineHeight(20)
        .width('100%')
        .padding({
          top: 28,
          bottom: 8,
          left: 30,
          right: 30
        })

      Column() {
        Text($r('app.string.Detail_ytbm'))
          .fontSize(16)
          .fontWeight(500)
          .fontColor($r('app.color.font_color_09'))
          .fontFamily('HarmonyHeiTi-Medium')
          .lineHeight(22)
          .width('100%')
          .margin({ top: 10 })

        Text(this.intentDetail?.bundleName)
          .fontSize(14)
          .fontWeight(400)
          .fontColor($r('app.color.font_color_06'))
          .fontFamily('HarmonyHeiTi')
          .lineHeight(20)
          .maxLines(1)
          .constraintSize({ maxWidth: '100%' })
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .width('100%')
          .margin({ bottom: 10 })

        Text($r('app.string.Detail_ytmc'))
          .fontSize(16)
          .fontWeight(500)
          .fontColor($r('app.color.font_color_09'))
          .fontFamily('HarmonyHeiTi-Medium')
          .lineHeight(22)
          .width('100%')
          .margin({ top: 10 })

        Text(this.intentDetail?.intentName)
          .fontSize(14)
          .fontWeight(400)
          .fontColor($r('app.color.font_color_06'))
          .fontFamily('HarmonyHeiTi')
          .lineHeight(20)
          .maxLines(1)
          .constraintSize({ maxWidth: '100%' })
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .width('100%')
          .margin({ bottom: 10 })

        Text($r('app.string.Detail_zxms'))
          .fontSize(16)
          .fontWeight(500)
          .fontColor($r('app.color.font_color_09'))
          .fontFamily('HarmonyHeiTi-Medium')
          .lineHeight(22)
          .width('100%')
          .margin({ top: 10 })

        Text(this.intentDetail?.intentType)
          .fontSize(14)
          .fontWeight(400)
          .fontColor($r('app.color.font_color_06'))
          .fontFamily('HarmonyHeiTi')
          .lineHeight(20)
          .maxLines(1)
          .constraintSize({ maxWidth: '100%' })
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .width('100%')
          .margin({ bottom: 10 })
      }
      .padding({
        top: 3,
        right: 12,
        bottom: 12,
        left: 12
      })
      .margin({ left: 18, right: 18 })
      .alignItems(HorizontalAlign.Start)
      .backgroundColor($r('app.color.background_white'))
      .borderRadius(20)
    }
  }
}