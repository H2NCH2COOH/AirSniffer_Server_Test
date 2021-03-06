Rails.application.routes.draw do
  get 'airsniffer/wxhandler'=>'airsniffer#wxhandler_get'
  post 'airsniffer/wxhandler'=>'airsniffer#wxhandler'
  
  get 'airsniffer/graph/:uid/:id'=>'airsniffer#graph'
  get 'airsniffer/chart/:uid/:id'=>'airsniffer#chart'
  get 'airsniffer/multichart/:uid'=>'airsniffer#multichart'
  
  get 'airsniffer/force_retrieve'=>'airsniffer#force_retrieve'
  get 'airsniffer/data_retrieve'=>'airsniffer#data_retrieve'
  get 'airsniffer/retrieve_at/:id'=>'airsniffer#retrieve_at'
  
  get 'airsniffer/new_device'
  get 'airsniffer/pre_register'
  get 'airsniffer/delete_device' 
  get 'airsniffer/pre_registered_dev'
  
  get 'airsniffer/test_req'

  get 'djcafe/sse'
  
  get '*path' => redirect('/404')
  # The priority is based upon order of creation: first created -> highest priority.
  # See how all your routes lay out with "rake routes".

  # You can have the root of your site routed with "root"
  # root 'welcome#index'

  # Example of regular route:
  #   get 'products/:id' => 'catalog#view'

  # Example of named route that can be invoked with purchase_url(id: product.id)
  #   get 'products/:id/purchase' => 'catalog#purchase', as: :purchase

  # Example resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Example resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Example resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Example resource route with more complex sub-resources:
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', on: :collection
  #     end
  #   end

  # Example resource route with concerns:
  #   concern :toggleable do
  #     post 'toggle'
  #   end
  #   resources :posts, concerns: :toggleable
  #   resources :photos, concerns: :toggleable

  # Example resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end
end
