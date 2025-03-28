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

export default class EventHub {
  private eventMap: Map<string, Array<Object>> = new Map<string, Array<Object>>();

  private getCloneArray(event: string): Array<Object> {
    if (this.eventMap.get(event)) {
      const array: Array<Object> = this.eventMap.get(event) as Array<Object>;
      const cloneArray = deepcopy<Array<Object>>(array) as Array<Object>;
      return cloneArray;
    }
    return new Array<Object>();
  }

  on(event: string, callback: Object) {
    if (!this.eventMap.get(event)) {
      this.eventMap.set(event, new Array<Object>());
    }
    let array: Array<Object> = this.eventMap.get(event) as Array<Object>;
    if (array.indexOf(callback) === -1) {
        array.push(callback);
    }
  }

  off(event: string, callback: Object) {
    if (this.eventMap.get(event)) {
      let cbArray: Array<Object> = this.eventMap.get(event) as Array<Object>;
      let index: number = cbArray.indexOf(callback);
      if (index > -1) {
        for (; index + 1 < cbArray.length; index++) {
          cbArray[index] = cbArray[index + 1];
        }
        cbArray.pop();
      }
    }
  }

  off(event: string) {
    if (this.eventMap.get(event)) {
      this.eventMap.delete(event);
    }
  }

  emit(event:string) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      let f = cloneArray[i] as () => void;
      f();
    }
  }

  emit<P1>(event:string, p1: P1) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      let f = cloneArray[i] as (p1: P1) => void;
      f(p1);
    }
  }

  emit<P1, P2>(event: string, p1: P1, p2: P2) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2) => void;
      f(p1, p2);
    }
  }

  emit<P1, P2, P3>(event: string, p1: P1, p2: P2, p3: P3) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3) => void;
      f(p1, p2, p3);
    }
  }

  emit<P1, P2, P3, P4>(event: string, p1: P1, p2: P2, p3: P3, p4: P4) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4) => void;
      f(p1, p2, p3, p4);
    }
  }

  emit<P1, P2, P3, P4, P5>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5) => void;
      f(p1, p2, p3, p4, p5);
    }
  }

  emit<P1, P2, P3, P4, P5, P6>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6) => void;
      f(p1, p2, p3, p4, p5, p6);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7) => void;
      f(p1, p2, p3, p4, p5, p6, p7);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13, p14: P14) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13, p14: P14) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13, p14: P14, p15: P15) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13, p14: P14, p15: P15) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15);
    }
  }

  emit<P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15, P16>(event: string, p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13, p14: P14, p15: P15, p16: P16) {
    const cloneArray: Array<Object> = this.getCloneArray(event);
    for (let i = 0; i < cloneArray.length; ++i) {
      const f = cloneArray[i] as (p1: P1, p2: P2, p3: P3, p4: P4, p5: P5, p6: P6, p7: P7, p8: P8, p9: P9, p10: P10, p11: P11, p12: P12, p13: P13, p14: P14, p15: P15, p16: P16) => void;
      f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, p16);
    }
  }
}