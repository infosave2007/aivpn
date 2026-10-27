//! Подписка на поток с устойчивым идентификатором задачи.

use iced::advanced::subscription::Hasher;
use iced::advanced::subscription::{self, EventStream, Recipe};
use iced::futures::{stream::BoxStream, Stream, StreamExt};
use iced::Subscription;
use std::hash::{Hash, Hasher as _};

pub fn from_stream<T: Send + 'static>(
    id: &'static str,
    stream: impl Stream<Item = T> + Send + 'static,
) -> Subscription<T> {
    struct NamedStream<T> {
        id: &'static str,
        stream: BoxStream<'static, T>,
    }

    impl<T: Send + 'static> Recipe for NamedStream<T> {
        type Output = T;

        fn hash(&self, state: &mut Hasher) {
            std::any::TypeId::of::<Self>().hash(state);
            state.write(self.id.as_bytes());
        }

        fn stream(self: Box<Self>, _input: EventStream) -> BoxStream<'static, T> {
            self.stream
        }
    }

    subscription::from_recipe(NamedStream {
        id,
        stream: stream.boxed(),
    })
}
