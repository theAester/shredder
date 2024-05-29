use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

pub struct ThreadPool {
    workers: Vec<Worker>,
    class_size: usize,
    assignments: Vec<usize>
}

type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    /// Create a new ThreadPool.
    ///
    /// The size is the number of threads in the pool.
    ///
    /// # Panics
    ///
    /// The `new` function will panic if the size is zero.
    pub fn new(pool_size: usize, class_size: usize) -> ThreadPool {
        assert!(pool_size > 0 && class_size > 0);


        let mut workers = Vec::with_capacity(pool_size);

        for id in 0..pool_size {
            let (sender, receiver) = mpsc::channel();
            workers.push(Worker::new(id, sender, receiver));
        }

        let mut assignments = vec![0usize; class_size];
        let mut j: usize = 0;
        for i in 0..class_size {
            assignments[i] = j;
            j += 1;
            j %= pool_size;
        }

        ThreadPool {
            workers,
            class_size,
            assignments,
        }
    }

    pub fn schedule<F>(&self, f: F, i: usize)
    where
        F: FnOnce() + Send + 'static,
    {
        let index = self.assignments[i];
        self.workers[index].start(f);
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        //drop(self.sender.take());

        for worker in &mut self.workers {
            println!("Shutting down worker {}", worker.id);
            drop(worker.sender.take());

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }

            println!("joined thread ({})", worker.id);
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
    sender: Option<mpsc::Sender<Job>>,
}

impl Worker {
    fn new(id: usize, sender: mpsc::Sender<Job>, receiver: mpsc::Receiver<Job>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver.recv();

            match message {
                Ok(job) => {
                    println!("Worker {id} got a job; executing.");

                    job();
                }
                Err(_) => {
                    println!("Worker {id} disconnected; shutting down.");
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
            sender: Some(sender),
        }
    }

    fn start<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.as_ref().unwrap().send(job).unwrap();
    }
}

impl Drop for Worker {
    fn drop(&mut self){
        drop(self.sender.take());
    }
}
