use core::ops::{Deref, DerefMut};

use hashbrown::HashMap;

pub struct DeviceHashMap<Key, Value>(Option<HashMap<Key, Value>>);

impl<Key, Value> DeviceHashMap<Key, Value> {
    pub fn new() -> Self {
        Self(Some(HashMap::new()))
    }

    pub fn replace(&mut self, mut new: DeviceHashMap<Key, Value>) -> DeviceHashMap<Key, Value> {
        let old = self.0.replace(new.0.take().unwrap());
        new.0 = old;
        new
    }
}

impl<Key, Value> Deref for DeviceHashMap<Key, Value> {
    type Target = HashMap<Key, Value>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl<Key, Value> DerefMut for DeviceHashMap<Key, Value> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}
