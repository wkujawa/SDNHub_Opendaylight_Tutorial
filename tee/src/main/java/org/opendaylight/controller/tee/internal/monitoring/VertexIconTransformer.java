/*
 * Copyright (C) 2015 Wiktor Kujawa

 Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 You may not use this file except in compliance with this License.
 You may obtain a copy of the License at

    http://www.gnu.org/licenses/gpl-3.0.txt

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.

 *
 */
package org.opendaylight.controller.tee.internal.monitoring;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import org.apache.commons.collections15.Transformer;

public class VertexIconTransformer implements Transformer<Device, Icon> {
    public int getHeight() {
        return 24;
    }

    public int getWidth() {
        return 24;
    }

    @Override
    public Icon transform(Device device) {
        if (device.getType() == DeviceType.HOST) {
            return new ImageIcon(this.getClass().getResource("/device.png"));
        } else if (device.getType() == DeviceType.SWITCH) {
            return new ImageIcon(this.getClass().getResource("/switch.png"));
        } else {
            return new ImageIcon(this.getClass().getResource("/unreachable.png"));
        }
    }
}
